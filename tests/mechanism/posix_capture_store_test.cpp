// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "nonblocking_refusal.h"

#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/target_observer.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <iterator>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

void require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

class temporary_directory final {
public:
  explicit temporary_directory(const char* prefix)
  {
    std::array<char, 96> pattern{};
    const std::string seed = std::string("/tmp/") + prefix + "-XXXXXX";
    require(seed.size() + 1U <= pattern.size(), "temporary path is too long");
    std::memcpy(pattern.data(), seed.c_str(), seed.size() + 1U);
    char* value = ::mkdtemp(pattern.data());
    if (!value)
      throw std::runtime_error("cannot create temporary directory");
    path_ = value;
  }

  ~temporary_directory()
  {
    const std::string command = "rm -rf -- '" + path_ + "'";
    static_cast<void>(std::system(command.c_str()));
  }

  [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
  std::string path_;
};

void write_file(const std::string& path, std::string_view bytes, mode_t mode)
{
  const int fd = ::open(path.c_str(),
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                        mode);
  require(fd >= 0, "cannot create capture test file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(fd, bytes.data() + offset,
                                  bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    require(count > 0, "cannot write capture test file");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(fd) == 0, "cannot close capture test file");
}

template<class Identity>
Identity identity(std::uint8_t seed)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string value = "v1:sha256:";
  for (std::size_t index = 0; index < 32U; ++index) {
    const auto byte = static_cast<std::uint8_t>(seed + index);
    value.push_back(digits[byte >> 4U]);
    value.push_back(digits[byte & 0x0fU]);
  }
  return Identity::parse(value);
}

pkgapply::application_attempt attempt(std::uint8_t seed)
{
  pkgapply::application_attempt_nonce::byte_array nonce{};
  for (std::size_t index = 0; index < nonce.size(); ++index)
    nonce[index] = static_cast<std::uint8_t>(seed + index + 3U);
  return pkgapply::application_attempt::make(
      identity<pkgapply::application_request_identity>(seed),
      identity<pkgapply::application_target_context_identity>(
          static_cast<std::uint8_t>(seed + 1U)),
      identity<pkgapply::mutation_backend_identity>(
          static_cast<std::uint8_t>(seed + 2U)),
      pkgapply::application_attempt_nonce::from_bytes(nonce));
}

const pkgapply::application_path_observation&
find(const pkgapply::backend_observation_batch& batch, std::string_view path)
{
  const auto parsed = pkgplan::package_path::parse(path);
  const auto* value = batch.find(parsed);
  if (!value)
    throw std::runtime_error("capture test observation missing");
  return *value;
}

std::string read_descriptor(int fd)
{
  std::string result;
  std::array<char, 64> buffer{};
  for (;;) {
    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    require(count >= 0, "cannot read captured regular descriptor");
    if (count == 0)
      break;
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  return result;
}

std::filesystem::path capture_record(const std::string& storage)
{
  std::filesystem::path attempt;
  for (const auto& entry : std::filesystem::directory_iterator(storage)) {
    const auto name = entry.path().filename().string();
    if (entry.is_directory() && name.rfind("capture-v1-", 0) == 0) {
      require(attempt.empty(), "capture test found multiple attempt directories");
      attempt = entry.path();
    }
  }
  require(!attempt.empty(), "capture test attempt directory is absent");

  std::filesystem::path record;
  for (const auto& entry : std::filesystem::directory_iterator(attempt)) {
    const auto name = entry.path().filename().string();
    if (entry.is_regular_file() && name.rfind("record-v1-", 0) == 0) {
      require(record.empty(), "capture test found multiple record files");
      record = entry.path();
    }
  }
  require(!record.empty(), "capture test record is absent");
  return record;
}

void corrupt_record_path(const std::string& storage, std::string_view path)
{
  const auto record = capture_record(storage);
  std::ifstream input(record, std::ios::binary);
  require(input.good(), "cannot open capture record for corruption");
  std::vector<unsigned char> bytes{
      std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  require(!input.bad(), "cannot read capture record for corruption");

  constexpr std::size_t checksum_offset = 8U + 2U + 8U;
  constexpr std::size_t body_offset = checksum_offset + 32U;
  require(bytes.size() > body_offset, "capture record is unexpectedly short");

  const auto found = std::search(
      bytes.begin() + static_cast<std::ptrdiff_t>(body_offset), bytes.end(),
      path.begin(), path.end());
  require(found != bytes.end(), "capture record path is absent");
  *found = static_cast<unsigned char>('/');

  EVP_MD_CTX* context = EVP_MD_CTX_new();
  require(context != nullptr, "cannot allocate capture test digest context");
  std::array<unsigned char, 32> digest{};
  unsigned int digest_size = 0;
  const bool hashed =
      EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
      EVP_DigestUpdate(
          context, bytes.data() + body_offset, bytes.size() - body_offset) == 1 &&
      EVP_DigestFinal_ex(context, digest.data(), &digest_size) == 1;
  EVP_MD_CTX_free(context);
  require(hashed && digest_size == digest.size(),
          "cannot recompute capture record checksum");
  std::copy(digest.begin(), digest.end(), bytes.begin() + checksum_offset);

  std::ofstream output(record, std::ios::binary | std::ios::trunc);
  require(output.good(), "cannot rewrite corrupt capture record");
  output.write(
      reinterpret_cast<const char*>(bytes.data()),
      static_cast<std::streamsize>(bytes.size()));
  require(output.good(), "cannot finish corrupt capture record");
}


void require_bounded_live_capture_descriptors(
    const pkgapply::posix::application_capture_store& store,
    const pkgapply::application_attempt& admitted_attempt,
    const pkgapply::backend_observation_batch& observations,
    const std::vector<pkgapply::old_object_capture_request>& requests)
{
  const pid_t child = ::fork();
  require(child >= 0, "cannot fork capture descriptor stress witness");
  if (child == 0) {
    struct rlimit original {};
    if (::getrlimit(RLIMIT_NOFILE, &original) != 0)
      _exit(90);
    const rlim_t wanted = std::min<rlim_t>(original.rlim_cur, 48U);
    if (wanted < 24U)
      _exit(91);
    struct rlimit constrained = original;
    constrained.rlim_cur = wanted;
    if (::setrlimit(RLIMIT_NOFILE, &constrained) != 0)
      _exit(92);

    try {
      std::vector<pkgapply::posix::captured_old_object> retained;
      retained.reserve(requests.size());
      for (const auto& request : requests) {
        const auto* observation = observations.find(request.path());
        if (observation == nullptr)
          _exit(93);
        auto loaded = store.load(admitted_attempt, request, *observation);
        if (!loaded)
          _exit(94);
        retained.push_back(std::move(*loaded));
      }
      if (retained.size() != requests.size())
        _exit(95);
    } catch (const std::exception& error) {
      std::cerr << "capture descriptor stress failed: " << error.what() << '\n';
      _exit(96);
    }
    _exit(0);
  }

  int status = 0;
  while (::waitpid(child, &status, 0) < 0) {
    if (errno == EINTR)
      continue;
    require(false, "cannot wait for capture descriptor stress witness");
  }
  require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "live capture authority consumes one descriptor per object");
}

} // namespace

int main()
{
  temporary_directory target("libpkgapply-capture-target");
  temporary_directory storage("libpkgapply-capture-store");
  const std::string usr = target.path() + "/usr";
  const std::string bin = usr + "/bin";
  require(::mkdir(usr.c_str(), 0755) == 0, "cannot create capture usr");
  require(::mkdir(bin.c_str(), 0755) == 0, "cannot create capture bin");
  write_file(bin + "/tool", "abcd", 0755);
  require(::link((bin + "/tool").c_str(), (bin + "/tool-link").c_str()) == 0,
          "cannot create capture hard link");
  require(::symlink("tool", (bin + "/tool-symlink").c_str()) == 0,
          "cannot create capture symbolic link");
  require(::mkfifo((bin + "/pipe").c_str(), 0644) == 0,
          "cannot create capture fifo");
  write_file(bin + "/later", "later", 0644);

  auto observer = pkgapply::posix::application_target_observer::open(target.path());
  const auto tool = pkgplan::package_path::parse("usr/bin/tool");
  const auto link = pkgplan::package_path::parse("usr/bin/tool-link");
  const auto batch = observer.observe(
      {tool,
       link,
       pkgplan::package_path::parse("usr/bin/tool-symlink"),
       pkgplan::package_path::parse("usr/bin/pipe"),
       pkgplan::package_path::parse("usr/bin/later")},
      {pkgapply::posix::target_hardlink_expectation(link, tool)});

  const auto admitted_attempt = attempt(20);
  auto store = pkgapply::posix::application_capture_store::open(
      storage.path(), target.path());

  const std::string stress = usr + "/capture-stress";
  require(::mkdir(stress.c_str(), 0755) == 0,
          "cannot create capture descriptor stress root");
  std::vector<pkgplan::package_path> stress_paths;
  std::vector<pkgapply::old_object_capture_request> stress_requests;
  constexpr std::size_t stress_count = 96U;
  stress_paths.reserve(stress_count);
  stress_requests.reserve(stress_count);
  for (std::size_t index = 0; index < stress_count; ++index) {
    const std::string leaf = "entry-" + std::to_string(index);
    require(::mkdir((stress + "/" + leaf).c_str(), 0755) == 0,
            "cannot create capture descriptor stress entry");
    auto path = pkgplan::package_path::parse("usr/capture-stress/" + leaf);
    stress_requests.emplace_back(path, false, true);
    stress_paths.push_back(std::move(path));
  }
  const auto stress_observations = observer.observe(stress_paths);
  for (const auto& request : stress_requests) {
    const auto* observation = stress_observations.find(request.path());
    require(observation != nullptr,
            "capture descriptor stress observation is absent");
    const auto result = store.capture(
        admitted_attempt, request, *observation);
    require(result.outcome() == pkgapply::backend_operation_outcome::completed &&
                result.exact_recovery_possible(),
            "capture descriptor stress authority was not retained");
  }
  require_bounded_live_capture_descriptors(
      store, admitted_attempt, stress_observations, stress_requests);

  const pkgapply::old_object_capture_request tool_request(tool, true, true);
  const auto tool_result = store.capture(
      admitted_attempt, tool_request, find(batch, "usr/bin/tool"));
  require(tool_result.outcome() == pkgapply::backend_operation_outcome::completed,
          "regular old object was not captured");
  require(!tool_result.exact_recovery_possible(),
          "unqualified multiply-linked regular object claimed exact recovery");

  const pkgapply::old_object_capture_request link_request(link, false, true);
  const auto link_result = store.capture(
      admitted_attempt, link_request, find(batch, "usr/bin/tool-link"));
  require(link_result.outcome() == pkgapply::backend_operation_outcome::completed,
          "hard-linked old object was not captured");
  require(link_result.exact_recovery_possible(),
          "proven hard-link relation lost exact recovery");

  const auto symlink_path = pkgplan::package_path::parse("usr/bin/tool-symlink");
  const pkgapply::old_object_capture_request symlink_request(
      symlink_path, true, false);
  const auto symlink_result = store.capture(
      admitted_attempt, symlink_request, find(batch, "usr/bin/tool-symlink"));
  require(symlink_result.outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              symlink_result.exact_recovery_possible(),
          "symbolic link was not captured exactly");

  const auto pipe_path = pkgplan::package_path::parse("usr/bin/pipe");
  const pkgapply::old_object_capture_request pipe_request(pipe_path, false, true);
  const auto pipe_result = store.capture(
      admitted_attempt, pipe_request, find(batch, "usr/bin/pipe"));
  require(pipe_result.outcome() == pkgapply::backend_operation_outcome::completed &&
              pipe_result.exact_recovery_possible(),
          "fifo was not captured exactly");

  store.synchronize(admitted_attempt);

  temporary_directory corrupt_storage("libpkgapply-capture-corrupt-store");
  auto corrupt_store = pkgapply::posix::application_capture_store::open(
      corrupt_storage.path(), target.path());
  const auto later_path = pkgplan::package_path::parse("usr/bin/later");
  const pkgapply::old_object_capture_request later_request(
      later_path, false, true);
  const auto corrupt_result = corrupt_store.capture(
      admitted_attempt, later_request, find(batch, "usr/bin/later"));
  require(corrupt_result.outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "capture corruption fixture was not published");
  corrupt_record_path(corrupt_storage.path(), "usr/bin/later");
  bool corrupt_record_rejected = false;
  try {
    static_cast<void>(corrupt_store.load(
        admitted_attempt, later_request, find(batch, "usr/bin/later")));
  }
  catch (const pkgapply::posix::capture_store_error& error) {
    corrupt_record_rejected =
        error.code() == pkgapply::posix::capture_store_error_code::record_invalid;
  }
  require(corrupt_record_rejected,
          "malformed capture record escaped the provider error domain");

  const auto fifo_record = capture_record(corrupt_storage.path());
  require(pkgapply::test::replace_with_fifo(fifo_record.string()),
          "cannot replace capture record with fifo");
  require(pkgapply::test::refuses_without_blocking([&]() {
    try {
      static_cast<void>(corrupt_store.load(
          admitted_attempt, later_request, find(batch, "usr/bin/later")));
    } catch (const pkgapply::posix::capture_store_error& error) {
      return error.code() ==
          pkgapply::posix::capture_store_error_code::record_read_failed;
    }
    return false;
  }), "capture store blocked on special-file record corruption");

  require(::unlink((bin + "/tool").c_str()) == 0,
          "cannot remove captured target object");
  write_file(bin + "/tool", "changed", 0600);
  require(::unlink((bin + "/tool-symlink").c_str()) == 0,
          "cannot remove captured target symlink");
  require(::symlink("elsewhere", (bin + "/tool-symlink").c_str()) == 0,
          "cannot replace captured target symlink");

  auto loaded = store.load(
      admitted_attempt, link_request, find(batch, "usr/bin/tool-link"));
  require(loaded.has_value(), "captured old object was not restart-visible");
  require(loaded->attempt().identity() == admitted_attempt.identity(),
          "captured old object changed its attempt binding");
  require(loaded->request().for_recovery() &&
              !loaded->request().for_rejected_object(),
          "captured old object changed its purpose binding");
  require(loaded->observation().object() ==
              find(batch, "usr/bin/tool-link").object(),
          "captured old object changed its admitted observation");
  {
    auto regular = loaded->open_regular();
    require(regular.size() == 4 &&
                read_descriptor(regular.descriptor()) == "abcd",
            "captured regular bytes changed after target mutation");
  }

  const auto repeated = store.capture(
      admitted_attempt, tool_request, find(batch, "usr/bin/tool"));
  require(repeated.outcome() == pkgapply::backend_operation_outcome::completed,
          "exact capture replay reread the changed target");

  bool binding_rejected = false;
  try {
    const pkgapply::old_object_capture_request changed_purpose(tool, true, false);
    static_cast<void>(store.load(
        admitted_attempt, changed_purpose, find(batch, "usr/bin/tool")));
  } catch (const pkgapply::posix::capture_store_error& error) {
    binding_rejected = error.code() ==
        pkgapply::posix::capture_store_error_code::binding_mismatch;
  }
  require(binding_rejected, "capture store accepted another purpose binding");

  const auto foreign_attempt = attempt(80);
  require(!store.load(
               foreign_attempt, tool_request, find(batch, "usr/bin/tool"))
               .has_value(),
          "capture store aliased another application attempt");

  const int storage_fd = ::open(
      storage.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  const int target_fd = ::open(
      target.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(storage_fd >= 0 && target_fd >= 0,
          "cannot open capture anchoring descriptors");
  auto anchored = pkgapply::posix::application_capture_store::from_directory_fds(
      storage_fd, target_fd);
  require(::close(storage_fd) == 0 && ::close(target_fd) == 0,
          "cannot close caller capture descriptors");
  const std::string moved_storage = storage.path() + "-moved";
  const std::string moved_target = target.path() + "-moved";
  require(::rename(storage.path().c_str(), moved_storage.c_str()) == 0,
          "cannot rename capture namespace");
  require(::rename(target.path().c_str(), moved_target.c_str()) == 0,
          "cannot rename capture target root");

  const auto later_result = anchored.capture(
      admitted_attempt, later_request, find(batch, "usr/bin/later"));
  require(later_result.outcome() == pkgapply::backend_operation_outcome::completed &&
              later_result.exact_recovery_possible(),
          "descriptor-anchored capture followed an old pathname");
  anchored.synchronize(admitted_attempt);

  require(::rename(moved_target.c_str(), target.path().c_str()) == 0,
          "cannot restore capture target pathname");
  require(::rename(moved_storage.c_str(), storage.path().c_str()) == 0,
          "cannot restore capture namespace pathname");

  return 0;
}

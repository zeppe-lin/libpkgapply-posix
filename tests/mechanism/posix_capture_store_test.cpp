// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/target_observer.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

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

  const auto later_path = pkgplan::package_path::parse("usr/bin/later");
  const pkgapply::old_object_capture_request later_request(
      later_path, false, true);
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

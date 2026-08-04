// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "active_namespace.h"

#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/payload_stage.h>
#include <libpkgapply-posix/target_observer.h>
#include <libpkgimage/package_archive.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

void
require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

class temporary_directory final {
public:
  explicit temporary_directory(std::string_view prefix)
  {
    std::string pattern = "/tmp/" + std::string(prefix) + "-XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    char* result = ::mkdtemp(writable.data());
    require(result != nullptr, "cannot create active recovery test directory");
    path_ = result;
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

std::array<std::uint8_t, 32>
sha256(std::string_view bytes)
{
  std::array<std::uint8_t, 32> digest {};
  unsigned int size = 0;
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  require(context != nullptr, "cannot allocate recovery digest context");
  require(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1,
          "cannot initialize recovery digest");
  require(EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1,
          "cannot update recovery digest");
  require(EVP_DigestFinal_ex(context, digest.data(), &size) == 1 &&
              size == digest.size(),
          "cannot finalize recovery digest");
  EVP_MD_CTX_free(context);
  return digest;
}

pkgimage::package_entry
regular(std::string path, std::string_view bytes, std::uint32_t mode = 0644)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::regular);
  entry.mode = mode;
  entry.uid = static_cast<std::uint64_t>(::geteuid());
  entry.gid = static_cast<std::uint64_t>(::getegid());
  entry.size = static_cast<std::uint64_t>(bytes.size());
  entry.mtime = 200;
  entry.mtime_nanoseconds = 50;
  entry.regular_content =
      pkgimage::regular_content_digest::from_sha256(sha256(bytes));
  return entry;
}

pkgimage::package_entry
directory(std::string path, std::uint32_t mode)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::directory);
  entry.mode = mode;
  entry.uid = static_cast<std::uint64_t>(::geteuid());
  entry.gid = static_cast<std::uint64_t>(::getegid());
  entry.mtime = 210;
  entry.mtime_nanoseconds = 60;
  return entry;
}

pkgimage::package_entry
hard_link(std::string path,
          std::string anchor,
          const pkgimage::package_entry& regular_anchor)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::hardlink);
  entry.mode = regular_anchor.mode;
  entry.uid = regular_anchor.uid;
  entry.gid = regular_anchor.gid;
  entry.mtime = regular_anchor.mtime;
  entry.mtime_nanoseconds = regular_anchor.mtime_nanoseconds;
  entry.hardlink_target = pkgimage::package_path::parse(std::move(anchor));
  return entry;
}

class memory_archive final : public pkgimage::package_archive {
public:
  memory_archive(std::vector<pkgimage::package_entry> entries,
                 std::vector<std::string> payloads)
      : image_(std::move(entries)), payloads_(std::move(payloads)),
        receipt_(pkgimage::archive_backend_identity::parse(
                     "test/pkgimage-active-recovery-v1"),
                 pkgimage::complete_archive_digest::from_sha256(
                     sha256("active recovery archive")),
                 image_.identity(), image_.size())
  {
    require(image_.size() == payloads_.size(),
            "active recovery payload count mismatch");
  }

  [[nodiscard]] const pkgimage::package_image& image() const noexcept override
  {
    return image_;
  }

  [[nodiscard]] const pkgimage::archive_inspection_receipt&
  inspection_receipt() const noexcept override
  {
    return receipt_;
  }

  void replay(const pkgimage::entry_selection& selection,
              pkgimage::payload_sink& sink) const override
  {
    selection.validate(image_);
    for (const auto& entry : image_.entries()) {
      if (!selection.contains(entry.id))
        continue;
      sink.begin(entry);
      const std::string& payload = payloads_.at(entry.id);
      if (!payload.empty()) {
        sink.write(
            entry,
            reinterpret_cast<const std::byte*>(payload.data()),
            payload.size());
      }
      sink.end(entry);
    }
  }

private:
  pkgimage::package_image image_;
  std::vector<std::string> payloads_;
  pkgimage::archive_inspection_receipt receipt_;
};

template<class Identity>
Identity
identity(std::uint8_t seed)
{
  constexpr char digits[] = "0123456789abcdef";
  std::string text = "v1:sha256:";
  for (std::size_t index = 0; index < 32U; ++index) {
    const auto byte = static_cast<std::uint8_t>(seed + index);
    text.push_back(digits[byte >> 4U]);
    text.push_back(digits[byte & 0x0fU]);
  }
  return Identity::parse(text);
}

pkgapply::application_attempt
attempt(std::uint8_t seed)
{
  pkgapply::application_attempt_nonce::byte_array bytes {};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(seed + index + 3U);
  return pkgapply::application_attempt::make(
      identity<pkgapply::application_request_identity>(seed),
      identity<pkgapply::application_target_context_identity>(seed + 1U),
      identity<pkgapply::mutation_backend_identity>(seed + 2U),
      pkgapply::application_attempt_nonce::from_bytes(bytes));
}

void
make_directory(const std::string& path, mode_t mode = 0755)
{
  require(::mkdir(path.c_str(), mode) == 0,
          "cannot create active recovery directory");
}

void
write_file(const std::string& path, std::string_view bytes, mode_t mode = 0644)
{
  const int descriptor = ::open(
      path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  require(descriptor >= 0, "cannot create active recovery file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(
        descriptor, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    require(count > 0, "cannot write active recovery file");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(descriptor) == 0,
          "cannot close active recovery file");
}

std::string
read_file(const std::string& path)
{
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  require(descriptor >= 0, "cannot open active recovery result");
  std::string result;
  std::array<char, 64> buffer {};
  for (;;) {
    const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    require(count >= 0, "cannot read active recovery result");
    if (count == 0)
      break;
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  require(::close(descriptor) == 0,
          "cannot close active recovery result");
  return result;
}

const pkgapply::application_path_observation&
observation(const std::vector<pkgapply::application_path_observation>& values,
            std::string_view path)
{
  const auto parsed = pkgplan::package_path::parse(path);
  for (const auto& value : values) {
    if (value.path() == parsed)
      return value;
  }
  throw std::runtime_error("active recovery observation is missing");
}

pkgapply::backend_active_effect_request
activate(const pkgimage::package_entry& value)
{
  return pkgapply::backend_active_effect_request::make(
      pkgplan::package_path::parse(value.path.string()),
      pkgplan::planned_active_outcome::activate_incoming,
      value.id);
}

pkgapply::backend_active_effect_request
remove_object(std::string_view path)
{
  return pkgapply::backend_active_effect_request::make(
      pkgplan::package_path::parse(path),
      pkgplan::planned_active_outcome::remove_observed);
}

bool
absent(const std::string& path)
{
  struct stat status {};
  return ::lstat(path.c_str(), &status) != 0 && errno == ENOENT;
}

void
load_capture(
    pkgapply::posix::application_capture_store& store,
    const pkgapply::application_attempt& active_attempt,
    const pkgapply::old_object_capture_request& request,
    const pkgapply::application_path_observation& admitted,
    std::vector<pkgapply::posix::captured_old_object>& captures)
{
  const auto result = store.capture(active_attempt, request, admitted);
  require(result.outcome() == pkgapply::backend_operation_outcome::completed,
          "active recovery capture did not complete");
  auto loaded = store.load(active_attempt, request, admitted);
  require(loaded.has_value(), "active recovery capture was not reloadable");
  captures.push_back(std::move(*loaded));
}

} // namespace

int
main()
{
  temporary_directory target("libpkgapply-active-recovery");
  temporary_directory payload_root("libpkgapply-recovery-payload");
  temporary_directory capture_root("libpkgapply-recovery-capture");

  make_directory(target.path() + "/usr");
  make_directory(target.path() + "/usr/bin");
  make_directory(target.path() + "/etc");
  make_directory(target.path() + "/etc/demo", 0755);
  write_file(target.path() + "/etc/demo/child", "retained");
  make_directory(target.path() + "/var");
  make_directory(target.path() + "/var/empty");
  make_directory(target.path() + "/tmp");

  write_file(target.path() + "/usr/bin/replace", "old-replace", 0640);
  write_file(target.path() + "/usr/bin/commit", "old-commit", 0644);
  write_file(target.path() + "/usr/bin/remove", "old-remove", 0600);
  write_file(target.path() + "/usr/bin/no-capture", "unrecoverable", 0644);
  write_file(target.path() + "/usr/bin/old-anchor", "old-group", 0644);
  require(::link((target.path() + "/usr/bin/old-anchor").c_str(),
                 (target.path() + "/usr/bin/old-link").c_str()) == 0,
          "cannot create old active hard-link group");

  auto new_anchor = regular("usr/bin/old-anchor", "new-group", 0750);
  auto new_link = hard_link(
      "usr/bin/old-link", "usr/bin/old-anchor", new_anchor);
  std::vector<pkgimage::package_entry> entries;
  entries.push_back(regular("usr/bin/new", "new-file", 0644));
  entries.push_back(regular("usr/bin/replace", "new-replace", 0755));
  entries.push_back(regular("usr/bin/commit", "new-commit", 0644));
  entries.push_back(directory("etc/demo", 0700));
  entries.push_back(regular("var/empty", "directory-replaced", 0644));
  entries.push_back(std::move(new_anchor));
  entries.push_back(std::move(new_link));

  memory_archive archive(
      std::move(entries),
      {"new-file", "new-replace", "new-commit", "",
       "directory-replaced", "new-group", ""});
  const auto selection =
      pkgimage::entry_selection::all_regular(archive.image());
  const auto active_attempt = attempt(40);

  auto payload_store = pkgapply::posix::application_payload_store::open(
      payload_root.path());
  {
    auto stage = payload_store.begin(
        active_attempt, archive.image(), selection);
    archive.replay(selection, *stage);
    require(stage->seal().outcome() ==
                pkgapply::backend_operation_outcome::completed,
            "active recovery payload stage did not seal");
  }
  auto payloads = payload_store.load(
      active_attempt, archive.image(), selection);
  require(payloads.has_value(),
          "active recovery payload stage disappeared");

  const std::vector<pkgplan::package_path> paths = {
      pkgplan::package_path::parse("usr/bin/new"),
      pkgplan::package_path::parse("usr/bin/replace"),
      pkgplan::package_path::parse("usr/bin/commit"),
      pkgplan::package_path::parse("usr/bin/remove"),
      pkgplan::package_path::parse("usr/bin/no-capture"),
      pkgplan::package_path::parse("usr/bin/old-anchor"),
      pkgplan::package_path::parse("usr/bin/old-link"),
      pkgplan::package_path::parse("etc/demo"),
      pkgplan::package_path::parse("var/empty"),
  };
  auto observer =
      pkgapply::posix::application_target_observer::open(target.path());
  auto batch = observer.observe(
      paths,
      {pkgapply::posix::target_hardlink_expectation(
          pkgplan::package_path::parse("usr/bin/old-link"),
          pkgplan::package_path::parse("usr/bin/old-anchor"))});
  auto before = batch.observations();

  auto capture_store = pkgapply::posix::application_capture_store::open(
      capture_root.path(), target.path());
  std::vector<pkgapply::posix::captured_old_object> captures;
  const std::vector<std::string_view> captured_paths = {
      "usr/bin/replace", "usr/bin/commit", "usr/bin/remove",
      "usr/bin/old-anchor",
      "usr/bin/old-link", "etc/demo", "var/empty",
  };
  for (std::string_view path : captured_paths) {
    const auto parsed = pkgplan::package_path::parse(path);
    const pkgapply::old_object_capture_request request(parsed, false, true);
    load_capture(
        capture_store, active_attempt, request,
        observation(before, path), captures);
  }
  capture_store.synchronize(active_attempt);

  const int root_descriptor = ::open(
      target.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(root_descriptor >= 0, "cannot open active recovery target root");
  auto active = pkgapply::posix::detail::application_active_namespace::bind(
      root_descriptor, active_attempt, archive.image(), &*payloads,
      before, std::move(captures));

  for (const auto& value : archive.image().entries()) {
    require(active.publish_incoming(activate(value)).outcome() ==
                pkgapply::backend_operation_outcome::completed,
            "active recovery incoming publication failed");
  }
  const auto committed_path =
      pkgplan::package_path::parse("usr/bin/commit");
  require(active.discard_recovery(committed_path).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              read_file(target.path() + "/usr/bin/commit") == "new-commit",
          "terminal active cleanup changed the published object");
  auto workspace =
      pkgapply::posix::detail::application_active_workspace::
          from_directory_fd(root_descriptor, active_attempt);
  require(workspace.open(committed_path).inspect().state() ==
              pkgapply::posix::detail::active_workspace_state::clear,
          "terminal active cleanup retained displaced old authority");

  require(active.remove(remove_object("usr/bin/remove")).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "captured active removal failed");
  require(active.remove(remove_object("usr/bin/no-capture")).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "uncaptured active removal failed");

  require(active.recover(
              pkgplan::package_path::parse("usr/bin/no-capture")).outcome() ==
              pkgapply::backend_operation_outcome::indeterminate,
          "missing recovery capture claimed exact restoration");
  require(active.recover(
              pkgplan::package_path::parse("usr/bin/remove")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              read_file(target.path() + "/usr/bin/remove") == "old-remove",
          "captured active removal was not restored");

  require(active.recover(
              pkgplan::package_path::parse("usr/bin/old-link")).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "old active hard-link member was not restored");
  require(active.recover(
              pkgplan::package_path::parse("usr/bin/old-anchor")).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "old active hard-link anchor was not restored");
  struct stat old_anchor {};
  struct stat old_link {};
  require(::stat((target.path() + "/usr/bin/old-anchor").c_str(),
                 &old_anchor) == 0 &&
              ::stat((target.path() + "/usr/bin/old-link").c_str(),
                     &old_link) == 0 &&
              old_anchor.st_dev == old_link.st_dev &&
              old_anchor.st_ino == old_link.st_ino &&
              read_file(target.path() + "/usr/bin/old-anchor") == "old-group",
          "active recovery recreated hard links as unrelated files");

  require(active.recover(
              pkgplan::package_path::parse("var/empty")).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "old active directory was not restored after a type change");
  struct stat restored_directory {};
  require(::stat((target.path() + "/var/empty").c_str(),
                 &restored_directory) == 0 &&
              S_ISDIR(restored_directory.st_mode),
          "directory recovery restored another object kind");

  require(active.recover(
              pkgplan::package_path::parse("etc/demo")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              read_file(target.path() + "/etc/demo/child") == "retained",
          "directory metadata recovery replaced retained children");
  require(active.recover(
              pkgplan::package_path::parse("usr/bin/replace")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              read_file(target.path() + "/usr/bin/replace") == "old-replace",
          "old regular replacement was not restored");
  require(active.recover(
              pkgplan::package_path::parse("usr/bin/new")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              absent(target.path() + "/usr/bin/new"),
          "prior absence was not restored");

  require(active.synchronize().status() ==
              pkgapply::application_durability_status::confirmed,
          "active recovery synchronization was not confirmed");
  require(absent(target.path() + "/usr/bin/no-capture"),
          "indeterminate recovery invented missing old bytes");
  require(::close(root_descriptor) == 0,
          "cannot close active recovery target root");
  return 0;
}

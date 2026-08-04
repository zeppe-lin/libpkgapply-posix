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
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
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
    require(result != nullptr, "cannot create active incoming test directory");
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
  require(context != nullptr, "cannot allocate test digest context");
  require(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1,
          "cannot initialize test digest");
  require(EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1,
          "cannot update test digest");
  require(EVP_DigestFinal_ex(context, digest.data(), &size) == 1 &&
              size == digest.size(),
          "cannot finalize test digest");
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
  entry.mtime = 100;
  entry.mtime_nanoseconds = 25;
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
  entry.mtime = 110;
  entry.mtime_nanoseconds = 35;
  return entry;
}

pkgimage::package_entry
symbolic_link(std::string path, std::string target)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::symlink);
  entry.mode = 0777;
  entry.uid = static_cast<std::uint64_t>(::geteuid());
  entry.gid = static_cast<std::uint64_t>(::getegid());
  entry.mtime = 120;
  entry.mtime_nanoseconds = 45;
  entry.symlink_target = std::move(target);
  return entry;
}

pkgimage::package_entry
fifo(std::string path)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::fifo);
  entry.mode = 0640;
  entry.uid = static_cast<std::uint64_t>(::geteuid());
  entry.gid = static_cast<std::uint64_t>(::getegid());
  entry.mtime = 130;
  entry.mtime_nanoseconds = 55;
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
                     "test/pkgimage-active-v1"),
                 pkgimage::complete_archive_digest::from_sha256(
                     sha256("active archive")),
                 image_.identity(), image_.size())
  {
    require(image_.size() == payloads_.size(),
            "active test payload count mismatch");
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

pkgapply::application_attempt_nonce
nonce(std::uint8_t seed)
{
  pkgapply::application_attempt_nonce::byte_array bytes {};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  return pkgapply::application_attempt_nonce::from_bytes(bytes);
}

pkgapply::application_attempt
attempt(std::uint8_t seed)
{
  return pkgapply::application_attempt::make(
      identity<pkgapply::application_request_identity>(seed),
      identity<pkgapply::application_target_context_identity>(seed + 1U),
      identity<pkgapply::mutation_backend_identity>(seed + 2U),
      nonce(seed + 3U));
}

void
make_directory(const std::string& path, mode_t mode = 0755)
{
  require(::mkdir(path.c_str(), mode) == 0, "cannot create test directory");
}

void
write_file(const std::string& path, std::string_view bytes, mode_t mode = 0644)
{
  const int descriptor = ::open(
      path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  require(descriptor >= 0, "cannot create active incoming test file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(
        descriptor, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    require(count > 0, "cannot write active incoming test file");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(descriptor) == 0,
          "cannot close active incoming test file");
}

std::string
read_file(const std::string& path)
{
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  require(descriptor >= 0, "cannot open active incoming result");
  std::string result;
  std::array<char, 64> buffer {};
  for (;;) {
    const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    require(count >= 0, "cannot read active incoming result");
    if (count == 0)
      break;
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  require(::close(descriptor) == 0, "cannot close active incoming result");
  return result;
}

const pkgimage::package_entry&
entry(const pkgimage::package_image& image, std::string_view path)
{
  const auto* found = image.find(pkgimage::package_path::parse(path));
  require(found != nullptr, "active incoming image entry is missing");
  return *found;
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
  throw std::runtime_error("active incoming observation is missing");
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
          "active incoming capture did not complete");
  auto loaded = store.load(active_attempt, request, admitted);
  require(loaded.has_value(), "active incoming capture was not reloadable");
  captures.push_back(std::move(*loaded));
}

pkgapply::backend_active_effect_request
activate(const pkgimage::package_entry& value)
{
  return pkgapply::backend_active_effect_request::make(
      pkgplan::package_path::parse(value.path.string()),
      pkgplan::planned_active_outcome::activate_incoming,
      value.id);
}

std::vector<pkgapply::application_path_observation>
observe(pkgapply::posix::application_target_observer& observer,
        const pkgimage::package_image& image)
{
  std::vector<pkgplan::package_path> paths;
  paths.reserve(image.size());
  for (const auto& value : image.entries())
    paths.push_back(pkgplan::package_path::parse(value.path.string()));
  return observer.observe(
      std::move(paths),
      {pkgapply::posix::target_hardlink_expectation(
          pkgplan::package_path::parse("usr/bin/tool-link"),
          pkgplan::package_path::parse("usr/bin/tool"))}).observations();
}

} // namespace

int
main()
{
  temporary_directory target("libpkgapply-active-incoming");
  temporary_directory payload_root("libpkgapply-active-payload");
  temporary_directory capture_root("libpkgapply-active-capture");

  make_directory(target.path() + "/usr");
  make_directory(target.path() + "/usr/bin");
  write_file(target.path() + "/usr/bin/tool", "old-tool", 0644);
  require(::link((target.path() + "/usr/bin/tool").c_str(),
                 (target.path() + "/usr/bin/tool-link").c_str()) == 0,
          "cannot create old active incoming hard-link group");
  make_directory(target.path() + "/etc");
  make_directory(target.path() + "/etc/demo", 0755);
  write_file(target.path() + "/etc/demo/child", "retained");
  make_directory(target.path() + "/run");
  make_directory(target.path() + "/var");
  make_directory(target.path() + "/var/empty-dir");
  make_directory(target.path() + "/var/nonempty");
  write_file(target.path() + "/var/nonempty/child", "stay");
  make_directory(target.path() + "/opt");
  write_file(target.path() + "/opt/legacy", "old");
  make_directory(target.path() + "/tmp");

  auto regular_tool = regular("usr/bin/tool", "new-tool", 0750);
  auto linked_tool = hard_link(
      "usr/bin/tool-link", "usr/bin/tool", regular_tool);
  std::vector<pkgimage::package_entry> entries;
  entries.push_back(std::move(regular_tool));
  entries.push_back(std::move(linked_tool));
  entries.push_back(symbolic_link("usr/bin/tool-sym", "tool"));
  entries.push_back(directory("etc/demo", 0700));
  entries.push_back(fifo("run/demo"));
  entries.push_back(regular("var/empty-dir", "directory-replaced"));
  entries.push_back(regular("var/nonempty", "must-not-replace"));
  entries.push_back(directory("opt/legacy", 0750));
  entries.push_back(regular("tmp/missing-payload", "payload"));

  memory_archive archive(
      std::move(entries),
      {"new-tool", "", "", "", "", "directory-replaced",
       "must-not-replace", "", "payload"});
  const auto selection =
      pkgimage::entry_selection::all_regular(archive.image());
  const auto active_attempt = attempt(20);

  auto payload_store = pkgapply::posix::application_payload_store::open(
      payload_root.path());
  {
    auto stage = payload_store.begin(
        active_attempt, archive.image(), selection);
    archive.replay(selection, *stage);
    require(stage->seal().outcome() ==
                pkgapply::backend_operation_outcome::completed,
            "active incoming payload stage did not seal");
  }
  auto payloads = payload_store.load(
      active_attempt, archive.image(), selection);
  require(payloads.has_value(), "active incoming payload stage disappeared");

  auto observer =
      pkgapply::posix::application_target_observer::open(target.path());
  const auto before = observe(observer, archive.image());
  auto capture_store = pkgapply::posix::application_capture_store::open(
      capture_root.path(), target.path());
  std::vector<pkgapply::posix::captured_old_object> captures;
  for (std::string_view path : {"usr/bin/tool", "usr/bin/tool-link"}) {
    const auto parsed = pkgplan::package_path::parse(path);
    const pkgapply::old_object_capture_request request(parsed, false, true);
    load_capture(
        capture_store, active_attempt, request,
        observation(before, path), captures);
  }
  capture_store.synchronize(active_attempt);

  const int root_descriptor = ::open(
      target.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(root_descriptor >= 0, "cannot open active incoming target root");

  auto active = pkgapply::posix::detail::application_active_namespace::bind(
      root_descriptor, active_attempt, archive.image(), &*payloads, before,
      std::move(captures));

  require(active.publish_incoming(
              activate(entry(archive.image(), "usr/bin/tool"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "regular active publication failed");
  require(read_file(target.path() + "/usr/bin/tool") == "new-tool",
          "regular active publication changed bytes");

  require(active.publish_incoming(
              activate(entry(
                  archive.image(), "usr/bin/tool-link"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "hard-link active publication failed");
  struct stat anchor {};
  struct stat linked {};
  require(::stat((target.path() + "/usr/bin/tool").c_str(), &anchor) == 0 &&
              ::stat((target.path() + "/usr/bin/tool-link").c_str(),
                     &linked) == 0 &&
              anchor.st_dev == linked.st_dev && anchor.st_ino == linked.st_ino,
          "hard-link active publication copied unrelated bytes");

  require(active.publish_incoming(
              activate(entry(archive.image(), "usr/bin/tool-sym"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "symbolic-link active publication failed");
  std::array<char, 32> link_target {};
  const ssize_t link_size = ::readlink(
      (target.path() + "/usr/bin/tool-sym").c_str(),
      link_target.data(), link_target.size());
  require(link_size == 4 &&
              std::string_view(link_target.data(), 4) == "tool",
          "symbolic-link active publication changed its target");

  require(active.publish_incoming(
              activate(entry(archive.image(), "etc/demo"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "existing directory metadata publication failed");
  require(read_file(target.path() + "/etc/demo/child") == "retained",
          "existing directory publication replaced managed children");
  struct stat directory_status {};
  require(::stat((target.path() + "/etc/demo").c_str(),
                 &directory_status) == 0 &&
              (directory_status.st_mode & 07777) == 0700,
          "existing directory publication missed requested mode");

  require(active.publish_incoming(
              activate(entry(archive.image(), "run/demo"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "FIFO active publication failed");
  struct stat fifo_status {};
  require(::lstat((target.path() + "/run/demo").c_str(), &fifo_status) == 0 &&
              S_ISFIFO(fifo_status.st_mode),
          "FIFO active publication created another object kind");

  require(active.publish_incoming(
              activate(entry(archive.image(), "var/empty-dir"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "empty directory to regular publication failed");
  require(read_file(target.path() + "/var/empty-dir") ==
              "directory-replaced",
          "empty directory replacement changed regular bytes");

  require(active.publish_incoming(
              activate(entry(archive.image(), "var/nonempty"))).outcome() ==
              pkgapply::backend_operation_outcome::failed,
          "non-empty directory replacement was not refused unchanged");
  require(read_file(target.path() + "/var/nonempty/child") == "stay",
          "non-empty directory refusal moved or removed its child");

  require(active.publish_incoming(
              activate(entry(archive.image(), "opt/legacy"))).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "regular to directory publication failed");
  require(::stat((target.path() + "/opt/legacy").c_str(),
                 &directory_status) == 0 &&
              S_ISDIR(directory_status.st_mode),
          "regular to directory publication created another object kind");

  auto no_payload =
      pkgapply::posix::detail::application_active_namespace::bind(
          root_descriptor, active_attempt, archive.image(), nullptr, before);
  require(no_payload.publish_incoming(
              activate(entry(
                  archive.image(), "tmp/missing-payload"))).outcome() ==
              pkgapply::backend_operation_outcome::failed,
          "regular publication accepted missing sealed payload authority");
  struct stat missing_status {};
  require(::fstatat(root_descriptor, "tmp/missing-payload", &missing_status,
                    AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT,
          "missing payload refusal changed the logical target");

  require(active.synchronize().status() ==
              pkgapply::application_durability_status::confirmed,
          "active namespace synchronization was not confirmed");
  require(::close(root_descriptor) == 0,
          "cannot close active incoming target root");

  bool hardlink_metadata_refused = false;
  try {
    auto anchor_entry = regular("usr/bin/bad-anchor", "bad");
    auto bad_link = hard_link(
        "usr/bin/bad-link", "usr/bin/bad-anchor", anchor_entry);
    bad_link.mode ^= 0111U;
    std::vector<pkgimage::package_entry> bad_entries;
    bad_entries.push_back(std::move(anchor_entry));
    bad_entries.push_back(std::move(bad_link));
    pkgimage::package_image bad_image(std::move(bad_entries));
    const int bad_root = ::open(
        target.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(bad_root >= 0, "cannot open hard-link refusal target root");
    auto bad_observer =
        pkgapply::posix::application_target_observer::from_directory_fd(
            bad_root);
    auto bad_before = observe(bad_observer, bad_image);
    static_cast<void>(
        pkgapply::posix::detail::application_active_namespace::bind(
            bad_root, attempt(90), bad_image, nullptr,
            std::move(bad_before)));
    require(::close(bad_root) == 0,
            "cannot close hard-link refusal target root");
  } catch (const std::exception&) {
    hardlink_metadata_refused = true;
  }
  require(hardlink_metadata_refused,
          "contradictory hard-link inode metadata was admitted");

  return 0;
}

// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "active_namespace.h"
#include "active_workspace.h"

#include <libpkgapply-posix/target_observer.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
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
  temporary_directory()
  {
    char pattern[] = "/tmp/libpkgapply-active-removal-XXXXXX";
    char* result = ::mkdtemp(pattern);
    require(result != nullptr, "cannot create active removal test root");
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
make_directory(const std::string& path)
{
  require(::mkdir(path.c_str(), 0755) == 0,
          "cannot create active removal directory");
}

void
write_file(const std::string& path, std::string_view bytes)
{
  const int descriptor = ::open(
      path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  require(descriptor >= 0, "cannot create active removal file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(
        descriptor, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    require(count > 0, "cannot write active removal file");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(descriptor) == 0, "cannot close active removal file");
}

pkgapply::backend_active_effect_request
remove_object(std::string_view path)
{
  return pkgapply::backend_active_effect_request::make(
      pkgplan::package_path::parse(path),
      pkgplan::planned_active_outcome::remove_observed);
}

pkgapply::backend_active_effect_request
remove_directory(std::string_view path)
{
  return pkgapply::backend_active_effect_request::make(
      pkgplan::package_path::parse(path),
      pkgplan::planned_active_outcome::remove_directory_if_empty);
}

bool
absent(const std::string& path)
{
  struct stat status {};
  return ::lstat(path.c_str(), &status) != 0 && errno == ENOENT;
}

} // namespace

int
main()
{
  temporary_directory root;
  make_directory(root.path() + "/usr");
  make_directory(root.path() + "/usr/bin");
  make_directory(root.path() + "/var");
  make_directory(root.path() + "/var/empty");
  make_directory(root.path() + "/var/nonempty");
  write_file(root.path() + "/var/nonempty/child", "retained");
  make_directory(root.path() + "/tmp");

  write_file(root.path() + "/usr/bin/tool", "old");
  write_file(root.path() + "/usr/bin/tool-anchor", "linked");
  require(::link((root.path() + "/usr/bin/tool-anchor").c_str(),
                 (root.path() + "/usr/bin/tool-link").c_str()) == 0,
          "cannot create active removal hard link");
  require(::symlink("tool", (root.path() + "/usr/bin/tool-sym").c_str()) == 0,
          "cannot create active removal symbolic link");
  require(::mkfifo((root.path() + "/usr/bin/pipe").c_str(), 0644) == 0,
          "cannot create active removal FIFO");
  write_file(root.path() + "/tmp/drift", "before");
  write_file(root.path() + "/tmp/collision", "before");

  const std::vector<pkgplan::package_path> paths = {
      pkgplan::package_path::parse("usr/bin/tool"),
      pkgplan::package_path::parse("usr/bin/tool-anchor"),
      pkgplan::package_path::parse("usr/bin/tool-link"),
      pkgplan::package_path::parse("usr/bin/tool-sym"),
      pkgplan::package_path::parse("usr/bin/pipe"),
      pkgplan::package_path::parse("var/empty"),
      pkgplan::package_path::parse("var/nonempty"),
      pkgplan::package_path::parse("tmp/drift"),
      pkgplan::package_path::parse("tmp/collision"),
  };
  auto observer =
      pkgapply::posix::application_target_observer::open(root.path());
  auto before = observer.observe(
      paths,
      {pkgapply::posix::target_hardlink_expectation(
          pkgplan::package_path::parse("usr/bin/tool-link"),
          pkgplan::package_path::parse("usr/bin/tool-anchor"))}).observations();
  const auto active_attempt = attempt(20);
  const int root_descriptor = ::open(
      root.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(root_descriptor >= 0, "cannot open active removal target root");

  auto active =
      pkgapply::posix::detail::application_active_namespace::
          bind_without_incoming(root_descriptor, active_attempt, before);

  require(active.remove(remove_object("usr/bin/tool")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              absent(root.path() + "/usr/bin/tool"),
          "regular active removal did not complete");
  require(active.remove(remove_object("usr/bin/tool-link")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              absent(root.path() + "/usr/bin/tool-link") &&
              !absent(root.path() + "/usr/bin/tool-anchor"),
          "hard-link active removal did not preserve its anchor");
  require(active.remove(remove_object("usr/bin/tool-sym")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              absent(root.path() + "/usr/bin/tool-sym"),
          "symbolic-link active removal did not complete");
  require(active.remove(remove_object("usr/bin/pipe")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              absent(root.path() + "/usr/bin/pipe"),
          "FIFO active removal did not complete");

  require(active.remove(remove_directory("var/empty")).outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              absent(root.path() + "/var/empty"),
          "empty active directory was not removed");
  require(active.remove(remove_directory("var/nonempty")).outcome() ==
              pkgapply::backend_operation_outcome::conditional_retained,
          "non-empty directory was not conditionally retained");
  require(!absent(root.path() + "/var/nonempty/child"),
          "conditional directory removal recursively changed children");

  write_file(root.path() + "/tmp/drift", "after");
  require(active.remove(remove_object("tmp/drift")).outcome() ==
              pkgapply::backend_operation_outcome::indeterminate,
          "external active-path drift was reported as unchanged failure");
  require(!absent(root.path() + "/tmp/drift"),
          "drift refusal removed the replacement object");

  auto workspace =
      pkgapply::posix::detail::application_active_workspace::
          from_directory_fd(root_descriptor, active_attempt);
  auto collision = workspace.open(
      pkgplan::package_path::parse("tmp/collision"));
  const int collision_descriptor = ::openat(
      collision.parent_descriptor(), collision.prepared_name().c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  require(collision_descriptor >= 0,
          "cannot create unresolved active workspace state");
  require(::close(collision_descriptor) == 0,
          "cannot close unresolved active workspace leaf");
  require(active.remove(remove_object("tmp/collision")).outcome() ==
              pkgapply::backend_operation_outcome::indeterminate,
          "unresolved active workspace was treated as a fresh removal");
  require(!absent(root.path() + "/tmp/collision"),
          "workspace collision changed the logical target");

  require(active.synchronize().status() ==
              pkgapply::application_durability_status::confirmed,
          "active removal synchronization was not confirmed");
  require(::close(root_descriptor) == 0,
          "cannot close active removal target root");
  return 0;
}

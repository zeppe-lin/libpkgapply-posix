// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "active_workspace.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

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
    char pattern[] = "/tmp/libpkgapply-active-workspace-XXXXXX";
    char* result = ::mkdtemp(pattern);
    require(result != nullptr, "cannot create active workspace test root");
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
  for (std::size_t index = 0; index < 32; ++index) {
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
create_file_at(int directory, const std::string& name)
{
  const int fd = ::openat(
      directory, name.c_str(),
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  require(fd >= 0, "cannot create active workspace test leaf");
  require(::close(fd) == 0, "cannot close active workspace test leaf");
}

} // namespace

int
main()
{
  temporary_directory root;
  require(::mkdir((root.path() + "/usr").c_str(), 0755) == 0,
          "cannot create usr directory");
  require(::mkdir((root.path() + "/usr/bin").c_str(), 0755) == 0,
          "cannot create bin directory");

  const int root_fd = ::open(
      root.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  require(root_fd >= 0, "cannot open active target root");
  auto first = pkgapply::posix::detail::application_active_workspace::
      from_directory_fd(root_fd, attempt(10));
  auto second = pkgapply::posix::detail::application_active_workspace::
      from_directory_fd(root_fd, attempt(20));
  require(::close(root_fd) == 0, "cannot close caller target-root descriptor");

  const auto path = pkgplan::package_path::parse("usr/bin/tool");
  auto workspace = first.open(path);
  auto repeated = first.open(path);
  auto foreign = second.open(path);
  require(workspace.leaf() == "tool",
          "active workspace changed the logical leaf");
  require(workspace.prepared_name() == repeated.prepared_name() &&
              workspace.displaced_name() == repeated.displaced_name(),
          "active workspace names are not deterministic");
  require(workspace.prepared_name() != foreign.prepared_name() &&
              workspace.displaced_name() != foreign.displaced_name(),
          "another attempt reused active workspace names");
  require(workspace.prepared_name().find(".libpkgapply-new-") == 0 &&
              workspace.displaced_name().find(".libpkgapply-old-") == 0,
          "active workspace names lack reserved prefixes");

  auto snapshot = workspace.inspect();
  require(snapshot.state() ==
              pkgapply::posix::detail::active_workspace_state::clear &&
              !snapshot.final_present(),
          "fresh absent workspace was not clear");

  create_file_at(workspace.parent_descriptor(), workspace.prepared_name());
  snapshot = workspace.inspect();
  require(snapshot.state() ==
              pkgapply::posix::detail::active_workspace_state::prepared &&
              snapshot.prepared_present() && !snapshot.displaced_present(),
          "prepared active workspace was not classified");

  create_file_at(workspace.parent_descriptor(), workspace.leaf());
  create_file_at(workspace.parent_descriptor(), workspace.displaced_name());
  require(::unlinkat(
              workspace.parent_descriptor(), workspace.leaf().c_str(), 0) == 0,
          "cannot model displaced logical target");
  snapshot = workspace.inspect();
  require(snapshot.state() ==
              pkgapply::posix::detail::active_workspace_state::displaced &&
              !snapshot.final_present(),
          "displaced active workspace was not classified");

  require(::unlinkat(
              workspace.parent_descriptor(),
              workspace.prepared_name().c_str(), 0) == 0,
          "cannot remove prepared workspace object");
  create_file_at(workspace.parent_descriptor(), workspace.leaf());
  snapshot = workspace.inspect();
  require(snapshot.state() == pkgapply::posix::detail::
              active_workspace_state::published_with_displaced_old,
          "published workspace with displaced old object was not classified");

  create_file_at(workspace.parent_descriptor(), workspace.prepared_name());
  snapshot = workspace.inspect();
  require(snapshot.state() ==
              pkgapply::posix::detail::active_workspace_state::contradictory,
          "contradictory active workspace was accepted");

  const std::string moved = root.path() + "-moved";
  require(::rename(root.path().c_str(), moved.c_str()) == 0,
          "cannot rename active target root");
  auto anchored = first.open(path).inspect();
  require(anchored.state() ==
              pkgapply::posix::detail::active_workspace_state::contradictory,
          "active workspace followed the replaced root pathname");
  require(::rename(moved.c_str(), root.path().c_str()) == 0,
          "cannot restore active target root pathname");

  temporary_directory outside;
  require(::symlink(
              outside.path().c_str(), (root.path() + "/escape").c_str()) == 0,
          "cannot create escaping active parent symlink");
  bool refused = false;
  try {
    static_cast<void>(first.open(
        pkgplan::package_path::parse("escape/object")));
  } catch (const pkgapply::posix::detail::active_workspace_error& error) {
    refused = error.code() == pkgapply::posix::detail::
        active_workspace_error_code::path_resolution_failed;
  }
  require(refused, "active workspace followed a symbolic-link parent");

  return 0;
}

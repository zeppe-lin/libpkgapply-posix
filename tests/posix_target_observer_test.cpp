// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/target_observer.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
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
  temporary_directory()
  {
    char pattern[] = "/tmp/libpkgapply-observer-XXXXXX";
    char* value = ::mkdtemp(pattern);
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
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                        mode);
  if (fd < 0)
    throw std::runtime_error("cannot create test file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(fd, bytes.data() + offset,
                                  bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      static_cast<void>(::close(fd));
      throw std::runtime_error("cannot write test file");
    }
    offset += static_cast<std::size_t>(count);
  }
  if (::close(fd) != 0)
    throw std::runtime_error("cannot close test file");
}

const pkgapply::application_path_observation&
find(const pkgapply::backend_observation_batch& batch, std::string_view path)
{
  const auto parsed = pkgplan::package_path::parse(path);
  const auto* value = batch.find(parsed);
  if (!value)
    throw std::runtime_error("observation missing from batch");
  return *value;
}

} // namespace

int main()
{
  temporary_directory root;
  const std::string usr = root.path() + "/usr";
  const std::string bin = usr + "/bin";
  require(::mkdir(usr.c_str(), 0755) == 0, "cannot create usr directory");
  require(::mkdir(bin.c_str(), 0755) == 0, "cannot create bin directory");
  write_file(bin + "/tool", "abcd", 0755);
  require(::link((bin + "/tool").c_str(), (bin + "/tool-link").c_str()) == 0,
          "cannot create hard link");
  require(::symlink("tool", (bin + "/tool-symlink").c_str()) == 0,
          "cannot create symbolic link");
  require(::mkfifo((bin + "/pipe").c_str(), 0644) == 0,
          "cannot create fifo");

  auto observer = pkgapply::posix::application_target_observer::open(root.path());
  const auto tool = pkgplan::package_path::parse("usr/bin/tool");
  const auto link = pkgplan::package_path::parse("usr/bin/tool-link");
  const auto batch = observer.observe(
      {pkgplan::package_path::parse("usr/bin"),
       pkgplan::package_path::parse("usr/bin/missing"),
       pkgplan::package_path::parse("usr/bin/pipe"),
       tool,
       link,
       pkgplan::package_path::parse("usr/bin/tool-symlink")},
      {pkgapply::posix::target_hardlink_expectation(link, tool)});

  const auto& regular = find(batch, "usr/bin/tool");
  require(regular.state() == pkgapply::fact_state::known && regular.object(),
          "regular file was not observed");
  require(regular.object()->kind() == pkgapply::completed_object_kind::regular,
          "regular kind was not retained");
  require(regular.object()->size().state() == pkgapply::fact_state::known &&
              *regular.object()->size().value() == 4,
          "regular size was not retained");
  require(regular.object()->regular_content().state() ==
              pkgapply::fact_state::known &&
              regular.object()->regular_content().value()->string() ==
                  "v1:sha256:88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589",
          "regular content digest was not retained");

  const auto& hardlink = find(batch, "usr/bin/tool-link");
  require(hardlink.state() == pkgapply::fact_state::known && hardlink.object(),
          "hard link was not observed");
  require(hardlink.object()->hardlink().state() == pkgapply::fact_state::known &&
              hardlink.object()->hardlink().value()->anchor() == tool,
          "hard-link anchor was not proven");

  const auto& symlink = find(batch, "usr/bin/tool-symlink");
  require(symlink.state() == pkgapply::fact_state::known && symlink.object() &&
              symlink.object()->kind() == pkgapply::completed_object_kind::symlink &&
              symlink.object()->symlink_target().state() == pkgapply::fact_state::known &&
              *symlink.object()->symlink_target().value() == "tool",
          "symbolic-link target was not retained");

  require(find(batch, "usr/bin").object()->kind() ==
              pkgapply::completed_object_kind::directory,
          "directory kind was not retained");
  require(find(batch, "usr/bin/pipe").object()->kind() ==
              pkgapply::completed_object_kind::fifo,
          "fifo kind was not retained");
  require(find(batch, "usr/bin/missing").state() ==
              pkgapply::fact_state::not_applicable,
          "missing path was not reported absent");

  const int root_fd = ::open(root.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(root_fd >= 0, "cannot open target root descriptor");
  auto anchored =
      pkgapply::posix::application_target_observer::from_directory_fd(root_fd);
  require(::close(root_fd) == 0, "cannot close caller root descriptor");
  const std::string moved = root.path() + "-moved";
  require(::rename(root.path().c_str(), moved.c_str()) == 0,
          "cannot rename target root");
  const auto anchored_batch = anchored.observe({tool});
  require(find(anchored_batch, "usr/bin/tool").state() == pkgapply::fact_state::known,
          "descriptor-anchored observer followed the old pathname");
  require(::rename(moved.c_str(), root.path().c_str()) == 0,
          "cannot restore target root pathname");

  temporary_directory outside;
  write_file(outside.path() + "/escaped", "x", 0644);
  require(::symlink(outside.path().c_str(), (root.path() + "/escape").c_str()) == 0,
          "cannot create escaping parent symlink");
  bool rejected = false;
  try {
    static_cast<void>(observer.observe(
        {pkgplan::package_path::parse("escape/escaped")}));
  } catch (const pkgapply::posix::target_observer_error& error) {
    rejected = error.code() ==
        pkgapply::posix::target_observer_error_code::path_resolution_failed;
  }
  require(rejected, "observer followed a symbolic-link parent outside the root");

  return 0;
}

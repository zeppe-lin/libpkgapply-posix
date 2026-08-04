// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/journal_store.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
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

template<class Identity>
Identity application_identity(std::uint8_t value)
{
  std::string text = "v1:sha256:";
  constexpr char hexadecimal[] = "0123456789abcdef";
  for (std::size_t index = 0; index < 32; ++index) {
    const auto byte = static_cast<std::uint8_t>(value + index);
    text += hexadecimal[(byte >> 4) & 0x0fU];
    text += hexadecimal[byte & 0x0fU];
  }
  return Identity::parse(text);
}

template<class Identity>
Identity planning_identity(std::uint8_t value)
{
  std::array<std::uint8_t, 32> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(value + index);
  return Identity::from_sha256(bytes);
}

pkgapply::application_journal_header header(std::uint8_t seed = 1)
{
  pkgapply::application_attempt_nonce::byte_array nonce{};
  for (std::size_t index = 0; index < nonce.size(); ++index)
    nonce[index] = static_cast<std::uint8_t>(seed + 20 + index);
  const auto request =
      application_identity<pkgapply::application_request_identity>(seed);
  const auto target = application_identity<
      pkgapply::application_target_context_identity>(seed + 1);
  const auto backend =
      application_identity<pkgapply::mutation_backend_identity>(seed + 2);
  const auto attempt = pkgapply::application_attempt::make(
      request, target, backend,
      pkgapply::application_attempt_nonce::from_bytes(nonce));
  return pkgapply::application_journal_header::make(
      pkgplan::operation_kind::install,
      request,
      planning_identity<pkgplan::operation_plan_identity>(seed + 3),
      attempt,
      target,
      application_identity<
          pkgapply::application_execution_control_identity>(seed + 4),
      application_identity<
          pkgapply::lease_bound_state_projection_identity>(seed + 5),
      application_identity<
          pkgapply::mutation_lease_instance_identity>(seed + 6),
      backend);
}

std::vector<pkgapply::application_journal_effect> effects()
{
  return {pkgapply::application_journal_effect::make(
      0,
      pkgapply::application_journal_effect_kind::publish_active_object,
      pkgplan::package_path::parse("usr/bin/tool"))};
}

pkgapply::application_journal_record initial_record()
{
  return pkgapply::application_journal_record::make(
      header(), pkgapply::application_journal_state::prepared, effects(), {});
}

pkgapply::application_journal_record successor_record()
{
  const auto graph = effects();
  return pkgapply::application_journal_record::make(
      header(), pkgapply::application_journal_state::mutating, graph,
      {{0, pkgapply::application_journal_event_kind::intent,
        graph[0].identity()}});
}

std::string only_snapshot(const std::string& directory)
{
  DIR* stream = ::opendir(directory.c_str());
  require(stream != nullptr, "cannot inspect journal-store test directory");
  std::string result;
  while (const auto* entry = ::readdir(stream)) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    require(result.empty(), "journal store left more than one snapshot file");
    result = name;
  }
  require(::closedir(stream) == 0, "cannot close journal-store test directory");
  require(!result.empty(), "journal store did not publish a snapshot file");
  return result;
}

void write_corruption(const std::string& path)
{
  const int fd = ::open(path.c_str(), O_WRONLY | O_TRUNC);
  require(fd >= 0, "cannot open journal snapshot for corruption test");
  const char bytes[] = "corrupt";
  require(::write(fd, bytes, sizeof(bytes)) ==
              static_cast<ssize_t>(sizeof(bytes)),
          "cannot corrupt journal snapshot");
  require(::close(fd) == 0, "cannot close corrupted journal snapshot");
}

} // namespace

int main()
{
  char root_template[] = "/tmp/libpkgapply-journal-store-XXXXXX";
  char* root_value = ::mkdtemp(root_template);
  require(root_value != nullptr, "cannot create journal-store test root");
  const std::string root = root_value;
  const std::string directory = root + "/journal";
  const std::string moved = root + "/moved";
  const std::string link = root + "/link";
  require(::mkdir(directory.c_str(), 0700) == 0,
          "cannot create journal-store test directory");

  auto store = pkgapply::posix::application_journal_store::open(directory);
  int directory_fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY);
  require(directory_fd >= 0, "cannot open journal-store test descriptor");
  auto duplicated =
      pkgapply::posix::application_journal_store::from_directory_fd(
          directory_fd);
  require(::close(directory_fd) == 0,
          "cannot close original journal-store test descriptor");
  const auto initial = initial_record();
  const auto successor = successor_record();
  const auto published_initial = store.publish(initial);
  require(published_initial.identity() == initial.identity(),
          "journal store changed the initial snapshot");

  const auto loaded_initial = store.load(initial.header().identity());
  require(loaded_initial && loaded_initial->identity() == initial.identity(),
          "journal store did not load the initial snapshot");
  const auto duplicated_initial =
      duplicated.load(initial.header().identity());
  require(duplicated_initial &&
              duplicated_initial->identity() == initial.identity(),
          "journal store did not retain its duplicated directory descriptor");
  require(!store.load(header(9).identity()),
          "journal store invented an unknown snapshot");

  const auto name = only_snapshot(directory);
  struct stat status {};
  require(::stat((directory + "/" + name).c_str(), &status) == 0,
          "cannot inspect journal snapshot mode");
  require((status.st_mode & 0777) == 0600,
          "journal snapshot mode is not private");

  require(store.publish(successor).identity() == successor.identity(),
          "journal store changed the successor snapshot");
  require(store.publish(successor).identity() == successor.identity(),
          "journal store did not accept exact idempotent publication");
  require(only_snapshot(directory) == name,
          "journal store left a temporary file after replacement");
  const auto loaded_successor = store.load(successor.header().identity());
  require(loaded_successor && loaded_successor->identity() == successor.identity(),
          "journal store did not replace the current snapshot");

  bool rejected = false;
  try {
    static_cast<void>(store.publish(initial));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
               pkgapply::posix::journal_store_error_code::snapshot_conflict;
  }
  require(rejected, "journal store accepted a stale replacement");

  require(::rename(directory.c_str(), moved.c_str()) == 0,
          "cannot rename journal-store directory");
  const auto anchored = store.load(successor.header().identity());
  require(anchored && anchored->identity() == successor.identity(),
          "journal store lost its directory anchor after rename");
  const auto duplicated_anchored =
      duplicated.load(successor.header().identity());
  require(duplicated_anchored &&
              duplicated_anchored->identity() == successor.identity(),
          "duplicated journal-store anchor did not survive rename");

  require(::symlink(moved.c_str(), link.c_str()) == 0,
          "cannot create journal-store directory symlink");
  rejected = false;
  try {
    static_cast<void>(pkgapply::posix::application_journal_store::open(link));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
               pkgapply::posix::journal_store_error_code::directory_open_failed;
  }
  require(rejected, "journal store followed a directory symlink");

  write_corruption(moved + "/" + name);
  rejected = false;
  try {
    static_cast<void>(store.load(successor.header().identity()));
  } catch (const pkgapply::posix::journal_store_error& error) {
    rejected = error.code() ==
               pkgapply::posix::journal_store_error_code::snapshot_corrupt;
  }
  require(rejected, "journal store accepted corrupt snapshot bytes");

  require(::unlink((moved + "/" + name).c_str()) == 0,
          "cannot remove journal-store test snapshot");
  require(::unlink(link.c_str()) == 0,
          "cannot remove journal-store test symlink");
  require(::rmdir(moved.c_str()) == 0,
          "cannot remove journal-store test directory");
  require(::rmdir(root.c_str()) == 0,
          "cannot remove journal-store test root");
  return 0;
}

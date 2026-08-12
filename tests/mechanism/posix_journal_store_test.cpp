// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "nonblocking_refusal.h"

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

pkgapply::lease_bound_state_projection state_projection(std::uint8_t seed)
{
  const auto lease = application_identity<
      pkgapply::mutation_lease_instance_identity>(seed + 6);
  return pkgapply::lease_bound_state_projection::make(
      lease,
      planning_identity<pkgplan::installed_state_snapshot_identity>(seed + 5),
      planning_identity<pkgplan::ownership_inventory_identity>(seed + 7),
      pkgapply::state_projection_completeness::complete,
      {pkgapply::projected_path_owners(
          pkgplan::package_path::parse("usr/bin/tool"),
          {planning_identity<pkgplan::installed_package_identity>(seed + 9)})},
      application_identity<pkgapply::state_projection_evidence_identity>(
          seed + 8));
}

bool same_projection(const pkgapply::lease_bound_state_projection& lhs,
                     const pkgapply::lease_bound_state_projection& rhs)
{
  return lhs.schema_version() == rhs.schema_version() &&
         lhs.identity() == rhs.identity() && lhs.lease() == rhs.lease() &&
         lhs.snapshot() == rhs.snapshot() &&
         lhs.ownership_inventory() == rhs.ownership_inventory() &&
         lhs.completeness() == rhs.completeness() &&
         lhs.paths() == rhs.paths() && lhs.evidence() == rhs.evidence();
}

pkgapply::application_journal_header header(
    std::uint8_t request_seed = 1,
    std::uint8_t attempt_seed = 1)
{
  pkgapply::application_attempt_nonce::byte_array nonce{};
  for (std::size_t index = 0; index < nonce.size(); ++index)
    nonce[index] = static_cast<std::uint8_t>(attempt_seed + 20 + index);
  const auto request =
      application_identity<pkgapply::application_request_identity>(request_seed);
  const auto target = application_identity<
      pkgapply::application_target_context_identity>(request_seed + 1);
  const auto backend =
      application_identity<pkgapply::mutation_backend_identity>(request_seed + 2);
  const auto attempt = pkgapply::application_attempt::make(
      request, target, backend,
      pkgapply::application_attempt_nonce::from_bytes(nonce));
  const auto projection = state_projection(request_seed);
  return pkgapply::application_journal_header::make(
      pkgplan::operation_kind::install,
      request,
      planning_identity<pkgplan::operation_plan_identity>(request_seed + 3),
      attempt,
      target,
      application_identity<
          pkgapply::application_execution_control_identity>(request_seed + 4),
      projection,
      projection.lease(),
      backend);
}

std::vector<pkgapply::application_journal_effect> effects()
{
  return {pkgapply::application_journal_effect::make(
      0,
      pkgapply::application_journal_effect_kind::publish_active_object,
      pkgplan::package_path::parse("usr/bin/tool"))};
}

pkgapply::application_journal_record initial_record(
    std::uint8_t request_seed = 1,
    std::uint8_t attempt_seed = 1)
{
  return pkgapply::application_journal_record::make(
      header(request_seed, attempt_seed),
      pkgapply::application_journal_state::prepared, effects(), {});
}

pkgapply::application_journal_record successor_record()
{
  const auto graph = effects();
  return pkgapply::application_journal_record::make(
      header(), pkgapply::application_journal_state::mutating, graph,
      {{0, pkgapply::application_journal_event_kind::intent,
        graph[0].identity()}});
}

std::vector<std::string> stored_files(const std::string& directory)
{
  DIR* stream = ::opendir(directory.c_str());
  require(stream != nullptr, "cannot inspect journal-store test directory");
  std::vector<std::string> result;
  while (const auto* entry = ::readdir(stream)) {
    const std::string name = entry->d_name;
    if (name != "." && name != "..")
      result.push_back(name);
  }
  require(::closedir(stream) == 0, "cannot close journal-store test directory");
  return result;
}

std::string journal_snapshot(const std::vector<std::string>& files)
{
  std::string result;
  for (const auto& name : files) {
    if (name.compare(0, 18, "journal-v1-sha256-") != 0)
      continue;
    require(result.empty(), "journal store left multiple journal snapshots");
    result = name;
  }
  require(!result.empty(), "journal store did not publish a journal snapshot");
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
  require(same_projection(
              published_initial.header().admitted_state_projection(),
              initial.header().admitted_state_projection()),
          "journal store changed admitted state-projection evidence");

  const auto loaded_initial = store.load(initial.header().identity());
  require(loaded_initial && loaded_initial->identity() == initial.identity(),
          "journal store did not load the initial snapshot");
  require(same_projection(loaded_initial->header().admitted_state_projection(),
                          initial.header().admitted_state_projection()),
          "journal store did not retain admitted state-projection evidence");
  const auto duplicated_initial =
      duplicated.load(initial.header().identity());
  require(duplicated_initial &&
              duplicated_initial->identity() == initial.identity(),
          "journal store did not retain its duplicated directory descriptor");
  require(!store.load(header(9).identity()),
          "journal store invented an unknown snapshot");
  const auto active_initial =
      store.load_active(initial.header().request());
  require(active_initial && active_initial->identity() == initial.identity(),
          "journal store did not index the active request journal");
  require(!store.load_active(header(9).request()),
          "journal store invented an active journal for an unknown request");

  const auto initial_files = stored_files(directory);
  require(initial_files.size() == 2U,
          "journal store did not retain one snapshot and one request index");
  const auto name = journal_snapshot(initial_files);
  struct stat status {};
  require(::stat((directory + "/" + name).c_str(), &status) == 0,
          "cannot inspect journal snapshot mode");
  require((status.st_mode & 0777) == 0600,
          "journal snapshot mode is not private");

  require(store.publish(successor).identity() == successor.identity(),
          "journal store changed the successor snapshot");
  require(store.publish(successor).identity() == successor.identity(),
          "journal store did not accept exact idempotent publication");
  require(stored_files(directory).size() == 2U,
          "journal store left a temporary file after replacement");
  const auto loaded_successor = store.load(successor.header().identity());
  require(loaded_successor && loaded_successor->identity() == successor.identity(),
          "journal store did not replace the current snapshot");
  const auto active_successor =
      store.load_active(successor.header().request());
  require(active_successor &&
              active_successor->identity() == successor.identity(),
          "journal store did not advance the active request index");

  const auto second_attempt = initial_record(1, 31);
  require(second_attempt.header().identity() != initial.header().identity(),
          "journal-store test did not construct a distinct attempt");
  require(store.publish(second_attempt).identity() == second_attempt.identity(),
          "journal store changed a second request attempt");
  const auto active_second =
      store.load_active(second_attempt.header().request());
  require(active_second &&
              active_second->identity() == second_attempt.identity(),
          "journal store did not replace the request index with a new attempt");
  require(store.load(successor.header().identity()) &&
              store.load(successor.header().identity())->identity() ==
                  successor.identity(),
          "journal store removed an older request attempt");

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
  const auto active_anchored =
      store.load_active(second_attempt.header().request());
  require(active_anchored &&
              active_anchored->identity() == second_attempt.identity(),
          "journal request index lost its directory anchor after rename");
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

  const std::string fifo_snapshot = moved + "/" + name;
  require(pkgapply::test::replace_with_fifo(fifo_snapshot),
          "cannot replace journal snapshot with fifo");
  require(pkgapply::test::refuses_without_blocking([&]() {
    try {
      static_cast<void>(store.load(successor.header().identity()));
    } catch (const pkgapply::posix::journal_store_error& error) {
      return error.code() ==
          pkgapply::posix::journal_store_error_code::snapshot_corrupt;
    }
    return false;
  }), "journal store blocked on special-file snapshot corruption");

  for (const auto& file : stored_files(moved)) {
    require(::unlink((moved + "/" + file).c_str()) == 0,
            "cannot remove journal-store test file");
  }
  require(::unlink(link.c_str()) == 0,
          "cannot remove journal-store test symlink");
  require(::rmdir(moved.c_str()) == 0,
          "cannot remove journal-store test directory");
  require(::rmdir(root.c_str()) == 0,
          "cannot remove journal-store test root");
  return 0;
}

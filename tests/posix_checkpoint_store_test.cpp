// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "checkpoint_test_fixture.h"

#include <libpkgapply-posix/checkpoint_store.h>

#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
void require(bool condition, std::string_view message)
{
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

std::string only_snapshot(const std::string& directory)
{
  DIR* stream = ::opendir(directory.c_str());
  require(stream != nullptr, "cannot inspect checkpoint-store directory");
  std::string result;
  while (const auto* entry = ::readdir(stream)) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    require(result.empty(), "checkpoint store left multiple files");
    result = name;
  }
  require(::closedir(stream) == 0, "cannot close checkpoint-store directory");
  require(!result.empty(), "checkpoint store published no file");
  return result;
}
}

int main()
{
  char root_template[] = "/tmp/libpkgapply-checkpoint-store-XXXXXX";
  char* root_value = ::mkdtemp(root_template);
  require(root_value != nullptr, "cannot create checkpoint-store root");
  const std::string root = root_value;
  const std::string directory = root + "/checkpoints";
  const std::string moved = root + "/moved";
  require(::mkdir(directory.c_str(), 0700) == 0,
          "cannot create checkpoint-store directory");

  const auto request = pkgapply::test::checkpoint_fixture::request();
  const auto journal =
      pkgapply::test::checkpoint_fixture::journal(request);
  const auto checkpoint =
      pkgapply::test::checkpoint_fixture::checkpoint(request, journal);
  auto store =
      pkgapply::posix::application_restart_checkpoint_store::open(directory);
  require(store.publish(journal, checkpoint).journal() == checkpoint.journal(),
          "checkpoint store changed published material");
  require(store.publish(journal, checkpoint).journal() == checkpoint.journal(),
          "checkpoint store rejected exact republication");

  const auto loaded = store.load(journal, request);
  require(loaded && loaded->completed_evidence() &&
              loaded->completed_evidence()->identity() ==
                  checkpoint.completed_evidence()->identity(),
          "checkpoint store did not load exact durable material");
  const auto name = only_snapshot(directory);
  struct stat status {};
  require(::stat((directory + "/" + name).c_str(), &status) == 0,
          "cannot inspect checkpoint mode");
  require((status.st_mode & 0777) == 0600,
          "checkpoint snapshot mode is not private");

  const auto another_journal =
      pkgapply::test::checkpoint_fixture::journal(request, 40);
  const auto another = pkgapply::test::checkpoint_fixture::checkpoint(
      request, another_journal, 40);
  require(store.publish(another_journal, another).journal() == another.journal(),
          "checkpoint store confused another journal record with this one");

  const auto conflicting = pkgapply::application_restart_checkpoint::make(
      checkpoint.journal(),
      checkpoint.admitted_observations(),
      checkpoint.incoming_payload(),
      checkpoint.captures(),
      checkpoint.rejected_effects(),
      checkpoint.active_effects(),
      checkpoint.recovery_effects(),
      checkpoint.synchronizations(),
      checkpoint.durability(),
      {pkgapply::test::checkpoint_fixture::application_identity<
          pkgapply::application_backend_evidence_identity>(99)},
      checkpoint.completed_evidence());
  bool rejected = false;
  try {
    static_cast<void>(store.publish(journal, conflicting));
  }
  catch (const pkgapply::posix::checkpoint_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::checkpoint_store_error_code::snapshot_conflict;
  }
  require(rejected,
          "checkpoint store rewrote an immutable journal checkpoint");

  require(::rename(directory.c_str(), moved.c_str()) == 0,
          "cannot rename checkpoint-store directory");
  const auto anchored = store.load(journal, request);
  require(anchored && anchored->journal() == checkpoint.journal(),
          "checkpoint store lost its directory anchor");

  const int fd = ::open((moved + "/" + name).c_str(), O_WRONLY | O_TRUNC);
  require(fd >= 0, "cannot open checkpoint for corruption test");
  const char corrupt[] = "corrupt";
  require(::write(fd, corrupt, sizeof(corrupt)) ==
              static_cast<ssize_t>(sizeof(corrupt)),
          "cannot corrupt checkpoint bytes");
  require(::close(fd) == 0, "cannot close corrupted checkpoint");
  rejected = false;
  try {
    static_cast<void>(store.load(journal, request));
  }
  catch (const pkgapply::posix::checkpoint_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::checkpoint_store_error_code::snapshot_corrupt;
  }
  require(rejected, "checkpoint store accepted corrupt bytes");

  DIR* stream = ::opendir(moved.c_str());
  require(stream != nullptr, "cannot inspect checkpoint cleanup directory");
  while (const auto* entry = ::readdir(stream)) {
    const std::string item = entry->d_name;
    if (item == "." || item == "..")
      continue;
    require(::unlink((moved + "/" + item).c_str()) == 0,
            "cannot remove checkpoint test file");
  }
  require(::closedir(stream) == 0, "cannot close checkpoint cleanup directory");
  require(::rmdir(moved.c_str()) == 0,
          "cannot remove checkpoint-store directory");
  require(::rmdir(root.c_str()) == 0,
          "cannot remove checkpoint-store root");
  return 0;
}

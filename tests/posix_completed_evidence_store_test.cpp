// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "checkpoint_test_fixture.h"

#include <libpkgapply-posix/completed_evidence_store.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
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

class temporary_directory final {
public:
  temporary_directory()
  {
    std::array<char, 80> pattern{};
    constexpr std::string_view seed =
        "/tmp/libpkgapply-completed-evidence-XXXXXX";
    static_assert(seed.size() + 1U <= pattern.size());
    std::memcpy(pattern.data(), seed.data(), seed.size());
    char* value = ::mkdtemp(pattern.data());
    if (value == nullptr)
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

std::string storage_name(
    const pkgapply::completed_application_evidence_identity& identity)
{
  constexpr std::string_view prefix = "v1:sha256:";
  require(identity.string().compare(0, prefix.size(), prefix) == 0,
          "test evidence identity has an unexpected representation");
  return "completed-v1-sha256-" +
         identity.string().substr(prefix.size()) + ".bin";
}

std::string only_record(const std::string& directory)
{
  DIR* stream = ::opendir(directory.c_str());
  require(stream != nullptr, "cannot inspect completed-evidence directory");
  std::string result;
  while (const auto* entry = ::readdir(stream)) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    require(result.empty(), "completed-evidence store left extra files");
    result = name;
  }
  require(::closedir(stream) == 0,
          "cannot close completed-evidence directory");
  require(!result.empty(), "completed-evidence store published no record");
  return result;
}

void require_same_evidence(
    const pkgapply::completed_application_evidence& actual,
    const pkgapply::completed_application_evidence& expected)
{
  require(actual.identity() == expected.identity(),
          "completed-evidence identity changed during storage");
  require(actual.kind() == expected.kind(),
          "completed-evidence operation kind changed during storage");
  require(actual.request() == expected.request(),
          "completed-evidence request changed during storage");
  require(actual.plan() == expected.plan(),
          "completed-evidence plan changed during storage");
  require(actual.attempt() == expected.attempt(),
          "completed-evidence attempt changed during storage");
  require(actual.target() == expected.target(),
          "completed-evidence target changed during storage");
  require(actual.control() == expected.control(),
          "completed-evidence control changed during storage");
  require(actual.state_projection() == expected.state_projection(),
          "completed-evidence state projection changed during storage");
  require(actual.journal() == expected.journal(),
          "completed-evidence journal changed during storage");
  require(actual.paths().size() == expected.paths().size() &&
              actual.paths().front().path() ==
                  expected.paths().front().path() &&
              actual.paths().front().active_status() ==
                  expected.paths().front().active_status() &&
              actual.paths().front().publication() ==
                  expected.paths().front().publication(),
          "completed-evidence path consequences changed during storage");
  require(actual.durability() == expected.durability(),
          "completed-evidence durability changed during storage");
  require(actual.backend_evidence() == expected.backend_evidence(),
          "completed-evidence backend proof changed during storage");
}

void corrupt_same_length(const std::string& path)
{
  const int fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
  require(fd >= 0, "cannot open completed-evidence record for corruption");
  struct stat status {};
  require(::fstat(fd, &status) == 0 && status.st_size > 64,
          "completed-evidence record is unexpectedly short");
  const off_t offset = status.st_size - 1;
  std::uint8_t byte = 0;
  require(::pread(fd, &byte, 1, offset) == 1,
          "cannot read completed-evidence corruption byte");
  byte ^= 0x01U;
  require(::pwrite(fd, &byte, 1, offset) == 1,
          "cannot write completed-evidence corruption byte");
  require(::close(fd) == 0,
          "cannot close corrupted completed-evidence record");
}

} // namespace

int main()
{
  using namespace pkgapply::test::checkpoint_fixture;

  const auto request = pkgapply::test::checkpoint_fixture::request();
  const auto journal = pkgapply::test::checkpoint_fixture::journal(request);
  const auto checkpoint =
      pkgapply::test::checkpoint_fixture::checkpoint(request, journal);
  require(checkpoint.completed_evidence().has_value(),
          "checkpoint fixture has no completed evidence");
  const auto evidence = *checkpoint.completed_evidence();

  const auto encoding =
      pkgapply::encode_completed_application_evidence(evidence);
  const auto decoded =
      pkgapply::decode_completed_application_evidence(encoding, request);
  require_same_evidence(decoded, evidence);
  require(pkgapply::encode_completed_application_evidence(decoded) == encoding,
          "completed-evidence encoding is not canonical");

  auto corrupted = encoding;
  require(corrupted.size() > 64U,
          "completed-evidence encoding is unexpectedly short");
  corrupted.back() ^= 0x01U;
  bool rejected = false;
  try {
    static_cast<void>(
        pkgapply::decode_completed_application_evidence(corrupted, request));
  }
  catch (const pkgapply::completed_application_evidence_codec_error& error) {
    rejected = error.code() ==
        pkgapply::completed_application_evidence_codec_error_code::
            checksum_mismatch;
  }
  require(rejected,
          "completed-evidence codec accepted same-length corruption");

  const auto foreign_request =
      pkgapply::test::checkpoint_fixture::request("foreign");
  rejected = false;
  try {
    static_cast<void>(pkgapply::decode_completed_application_evidence(
        encoding, foreign_request));
  }
  catch (const pkgapply::completed_application_evidence_codec_error& error) {
    rejected = error.code() ==
        pkgapply::completed_application_evidence_codec_error_code::
            request_mismatch;
  }
  require(rejected, "completed-evidence codec accepted a foreign request");

  temporary_directory root;
  const std::string directory = root.path() + "/evidence";
  const std::string moved = root.path() + "/moved";
  require(::mkdir(directory.c_str(), 0700) == 0,
          "cannot create completed-evidence directory");

  auto store =
      pkgapply::posix::completed_application_evidence_store::open(directory);
  const int directory_fd =
      ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(directory_fd >= 0,
          "cannot open caller completed-evidence directory descriptor");
  auto duplicate = pkgapply::posix::completed_application_evidence_store::
      from_directory_fd(directory_fd);
  require(::close(directory_fd) == 0,
          "cannot close caller completed-evidence directory descriptor");

  const mode_t old_mask = ::umask(0777);
  const auto published = store.publish(evidence, request);
  ::umask(old_mask);
  require(published == evidence.identity(),
          "completed-evidence store changed the published identity");
  require(store.publish(evidence, request) == evidence.identity(),
          "completed-evidence store rejected exact republication");

  const auto missing = duplicate.load(
      application_identity<pkgapply::completed_application_evidence_identity>(
          190),
      request);
  require(!missing, "completed-evidence store invented a missing record");

  const auto loaded = duplicate.load(evidence.identity(), request);
  require(loaded.has_value(),
          "completed-evidence store did not load published evidence");
  require_same_evidence(*loaded, evidence);

  const auto name = only_record(directory);
  require(name == storage_name(evidence.identity()),
          "completed-evidence store used a noncanonical record name");
  struct stat status {};
  require(::stat((directory + "/" + name).c_str(), &status) == 0,
          "cannot inspect completed-evidence record mode");
  require(S_ISREG(status.st_mode) && (status.st_mode & 0777) == 0600,
          "completed-evidence record is not a private regular file");

  rejected = false;
  try {
    static_cast<void>(store.publish(evidence, foreign_request));
  }
  catch (const pkgapply::posix::completed_evidence_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::completed_evidence_store_error_code::record_invalid;
  }
  require(rejected,
          "completed-evidence store accepted a foreign immutable request");

  require(::rename(directory.c_str(), moved.c_str()) == 0,
          "cannot rename completed-evidence directory");
  const auto anchored = store.load(evidence.identity(), request);
  require(anchored.has_value(),
          "completed-evidence store lost its directory anchor");
  require_same_evidence(*anchored, evidence);
  store.synchronize();

  corrupt_same_length(moved + "/" + name);
  rejected = false;
  try {
    static_cast<void>(duplicate.load(evidence.identity(), request));
  }
  catch (const pkgapply::posix::completed_evidence_store_error& error) {
    rejected = error.code() ==
        pkgapply::posix::completed_evidence_store_error_code::record_invalid;
  }
  require(rejected, "completed-evidence store accepted corrupt bytes");
  return 0;
}

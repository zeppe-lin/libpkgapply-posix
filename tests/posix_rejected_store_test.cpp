// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/payload_stage.h>
#include <libpkgapply-posix/rejected_store.h>
#include <libpkgapply-posix/target_observer.h>
#include <libpkgimage/package_archive.h>

#include "plan_fixture.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

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

std::array<std::uint8_t, 32> sha256(std::string_view bytes)
{
  std::array<std::uint8_t, 32> digest{};
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

std::string hexadecimal(const std::uint8_t* bytes, std::size_t size)
{
  static constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(size * 2U);
  for (std::size_t index = 0; index < size; ++index) {
    result.push_back(digits[bytes[index] >> 4U]);
    result.push_back(digits[bytes[index] & 0x0fU]);
  }
  return result;
}

pkgimage::package_entry regular_entry(
    std::string path, std::string_view bytes, std::uint32_t mode = 0644)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::regular);
  entry.mode = mode;
  entry.uid = 0;
  entry.gid = 0;
  entry.size = static_cast<std::uint64_t>(bytes.size());
  entry.mtime = 100;
  entry.mtime_nanoseconds = 200;
  entry.regular_content =
      pkgimage::regular_content_digest::from_sha256(sha256(bytes));
  return entry;
}

pkgimage::package_entry hardlink_entry(
    std::string path, std::string anchor)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::hardlink);
  entry.mode = 0755;
  entry.uid = 0;
  entry.gid = 0;
  entry.mtime = 101;
  entry.mtime_nanoseconds = 201;
  entry.hardlink_target = pkgimage::package_path::parse(std::move(anchor));
  return entry;
}

pkgimage::package_entry symlink_entry(
    std::string path, std::string target)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::symlink);
  entry.mode = 0777;
  entry.uid = 0;
  entry.gid = 0;
  entry.mtime = 102;
  entry.mtime_nanoseconds = 202;
  entry.symlink_target = std::move(target);
  return entry;
}

pkgimage::package_entry character_entry(std::string path)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::character_device);
  entry.mode = 0600;
  entry.uid = 0;
  entry.gid = 0;
  entry.mtime = 103;
  entry.mtime_nanoseconds = 203;
  entry.device = pkgimage::device_number{1, 3};
  return entry;
}

pkgimage::package_entry directory_entry(std::string path)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::directory);
  entry.mode = 0750;
  entry.uid = 0;
  entry.gid = 0;
  entry.mtime = 104;
  entry.mtime_nanoseconds = 204;
  return entry;
}

pkgimage::package_entry fifo_entry(std::string path)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::fifo);
  entry.mode = 0620;
  entry.uid = 0;
  entry.gid = 0;
  entry.mtime = 105;
  entry.mtime_nanoseconds = 205;
  return entry;
}

std::vector<pkgimage::package_entry> incoming_entries()
{
  std::vector<pkgimage::package_entry> entries;
  entries.reserve(4);
  entries.push_back(regular_entry("usr/bin/tool", "abcd", 0755));
  entries.push_back(hardlink_entry("usr/bin/tool-hard", "usr/bin/tool"));
  entries.push_back(symlink_entry("usr/bin/tool-link", "tool"));
  entries.push_back(character_entry("dev/tool-control"));
  return entries;
}

std::vector<pkgimage::package_entry> nonregular_entries()
{
  std::vector<pkgimage::package_entry> entries;
  entries.reserve(4);
  entries.push_back(directory_entry("var/lib/tool"));
  entries.push_back(symlink_entry("usr/bin/tool-current", "tool"));
  entries.push_back(fifo_entry("run/tool.pipe"));
  entries.push_back(character_entry("dev/tool-status"));
  return entries;
}

class memory_archive final : public pkgimage::package_archive {
public:
  memory_archive()
      : image_(incoming_entries()),
        receipt_(pkgimage::archive_backend_identity::parse(
                     "test/pkgimage-rejected-memory-v1"),
                 pkgimage::complete_archive_digest::from_sha256(
                     sha256("rejected archive")),
                 image_.identity(), image_.size())
  {
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
      if (entry.path.string() == "usr/bin/tool") {
        constexpr std::string_view bytes = "abcd";
        sink.write(entry,
                   reinterpret_cast<const std::byte*>(bytes.data()),
                   bytes.size());
      }
      sink.end(entry);
    }
  }

private:
  pkgimage::package_image image_;
  pkgimage::archive_inspection_receipt receipt_;
};

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

const pkgimage::package_entry& image_entry(
    const pkgimage::package_image& image, std::string_view path)
{
  const auto* result = image.find(pkgimage::package_path::parse(path));
  if (result == nullptr)
    throw std::runtime_error("rejected-store test image entry missing");
  return *result;
}

pkgplan::installation_plan staged_incoming_plan(
    std::uint8_t seed,
    const std::vector<pkgimage::package_entry>& entries)
{
  const pkgapply::test::fixture::planning_authorities authorities(
      identity<pkgplan::target_system_context_identity>(seed));
  std::vector<pkgplan::package_path> explicit_paths;
  explicit_paths.reserve(entries.size());
  for (const auto& entry : entries) {
    explicit_paths.push_back(pkgplan::package_path::parse(entry.path.string()));
  }
  std::sort(explicit_paths.begin(), explicit_paths.end());
  explicit_paths.erase(
      std::unique(explicit_paths.begin(), explicit_paths.end()),
      explicit_paths.end());

  std::vector<pkgplan::target_path_observation> observations;
  for (const auto& path : explicit_paths) {
    observations.push_back(pkgplan::target_path_observation::absent(path));
  }
  for (const auto& path : explicit_paths) {
    auto parent = path.parent();
    while (parent) {
      if (!std::binary_search(
              explicit_paths.begin(), explicit_paths.end(), *parent)) {
        const auto duplicate = std::find_if(
            observations.begin(), observations.end(),
            [&parent](const auto& observation) {
              return observation.path() == *parent;
            });
        if (duplicate == observations.end()) {
          observations.push_back(pkgplan::target_path_observation::present(
              pkgplan::filesystem_object_fact(
                  *parent,
                  pkgapply::test::fixture::directory_object())));
        }
      }
      parent = parent->parent();
    }
  }
  const auto policy = pkgapply::test::fixture::policy_snapshot(
      authorities,
      pkgapply::test::fixture::path_policy(
          pkgplan::incoming_path_policy::retain(
              pkgplan::rejected_object_policy::stage,
              pkgplan::retained_active_ownership_policy::
                  do_not_claim_operated_package)));
  return pkgapply::test::fixture::installation_plan(
      authorities, entries, std::move(observations), {}, policy);
}

std::string read_descriptor(int fd)
{
  std::string result;
  std::array<char, 64> buffer{};
  for (;;) {
    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    require(count >= 0, "cannot read rejected regular descriptor");
    if (count == 0)
      break;
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  return result;
}

void write_file(const std::string& path, std::string_view bytes, mode_t mode)
{
  const int fd = ::open(path.c_str(),
                        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                        mode);
  require(fd >= 0, "cannot create rejected-store fixture file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(fd, bytes.data() + offset,
                                  bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    require(count > 0, "cannot write rejected-store fixture file");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(fd) == 0, "cannot close rejected-store fixture file");
}

const pkgapply::application_path_observation& find_observation(
    const pkgapply::backend_observation_batch& batch,
    const pkgplan::package_path& path)
{
  const auto* result = batch.find(path);
  if (result == nullptr)
    throw std::runtime_error("rejected-store observation missing");
  return *result;
}

} // namespace

int main()
{
  temporary_directory payload_directory("libpkgapply-rejected-payload");
  temporary_directory rejected_directory("libpkgapply-rejected-store");
  memory_archive archive;
  const auto admitted_attempt = attempt(20);
  const auto incoming_plan = staged_incoming_plan(40, archive.image().entries());
  const auto& admitted_plan = incoming_plan.identity();
  const auto selection = pkgimage::entry_selection::all_regular(archive.image());

  auto payload_store = pkgapply::posix::application_payload_store::open(
      payload_directory.path());
  {
    auto stage = payload_store.begin(
        admitted_attempt, archive.image(), selection);
    archive.replay(selection, *stage);
    require(stage->seal().outcome() ==
                pkgapply::backend_operation_outcome::completed,
            "incoming payload stage did not seal");
  }
  auto payloads = payload_store.load(
      admitted_attempt, archive.image(), selection);
  require(payloads.has_value(), "sealed incoming payloads disappeared");

  auto rejected_store =
      pkgapply::posix::application_rejected_object_store::open(
          rejected_directory.path());

  const auto metadata_attempt = attempt(21);
  const pkgimage::package_image metadata_image(nonregular_entries());
  const auto metadata_operation =
      staged_incoming_plan(41, metadata_image.entries());
  const auto& metadata_plan = metadata_operation.identity();
  const auto empty_selection =
      pkgimage::entry_selection::all_regular(metadata_image);
  require(empty_selection.size() == 0,
          "non-regular image unexpectedly selected payloads");

  const auto publish_metadata = [&](std::string_view path) {
    const auto& entry = image_entry(metadata_image, path);
    const auto request = pkgapply::test::fixture::rejected_request(
        metadata_operation,
        pkgplan::package_path::parse(entry.path.string()));
    const auto result = rejected_store.publish_incoming(
        metadata_attempt, metadata_plan, request, metadata_image);
    require(result.outcome() ==
                pkgapply::backend_operation_outcome::completed &&
                result.record().has_value(),
            "non-regular rejected object required payload staging");
    return rejected_store.load(
        metadata_attempt, metadata_plan, request);
  };

  auto metadata_directory = publish_metadata("var/lib/tool");
  auto metadata_symlink = publish_metadata("usr/bin/tool-current");
  auto metadata_fifo = publish_metadata("run/tool.pipe");
  auto metadata_character = publish_metadata("dev/tool-status");
  require(metadata_directory.has_value() &&
              metadata_directory->observation().object()->kind() ==
                  pkgapply::completed_object_kind::directory &&
              metadata_symlink.has_value() &&
              metadata_symlink->observation().object()->symlink_target().value() ==
                  std::optional<std::string>("tool") &&
              metadata_fifo.has_value() &&
              metadata_fifo->observation().object()->kind() ==
                  pkgapply::completed_object_kind::fifo &&
              metadata_character.has_value() &&
              metadata_character->observation().object()->device().value() ==
                  std::optional<pkgapply::completed_device_number>({1, 3}),
          "empty-payload rejected records lost typed image facts");

  const auto& regular = image_entry(archive.image(), "usr/bin/tool");
  const auto regular_request = pkgapply::test::fixture::rejected_request(
      incoming_plan, pkgplan::package_path::parse(regular.path.string()));
  bool regular_without_payload_rejected = false;
  try {
    static_cast<void>(rejected_store.publish_incoming(
        admitted_attempt, admitted_plan, regular_request, archive.image()));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    regular_without_payload_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::source_unavailable;
  }
  require(regular_without_payload_rejected,
          "regular rejected object published without sealed payload authority");
  require(!rejected_store.load(
               admitted_attempt, admitted_plan, regular_request).has_value(),
          "failed regular publication left a completed rejected record");

  const auto regular_result = rejected_store.publish_incoming(
      admitted_attempt, admitted_plan, regular_request, archive.image(), *payloads);
  require(regular_result.outcome() ==
              pkgapply::backend_operation_outcome::completed &&
              regular_result.record().has_value() &&
              !regular_result.evidence().empty(),
          "incoming regular rejected object was not published");

  auto loaded_regular = rejected_store.load(
      admitted_attempt, admitted_plan, regular_request);
  require(loaded_regular.has_value(),
          "incoming regular rejected record was not restart-visible");
  require(loaded_regular->source() ==
              pkgapply::posix::rejected_object_source::incoming &&
              loaded_regular->identity() == *regular_result.record(),
          "incoming rejected record changed authority or identity");
  require(loaded_regular->observation().object()->provenance() ==
              pkgapply::object_fact_provenance::incoming_image,
          "incoming rejected record lost image provenance");
  {
    auto object = loaded_regular->open_regular();
    require(object.size() == 4 &&
                read_descriptor(object.descriptor()) == "abcd",
            "incoming rejected regular payload changed");
  }

  const auto repeated_regular = rejected_store.publish_incoming(
      admitted_attempt, admitted_plan, regular_request, archive.image(), *payloads);
  require(repeated_regular.record() == regular_result.record(),
          "exact rejected publication was not idempotent");

  const auto& hardlink = image_entry(archive.image(), "usr/bin/tool-hard");
  const auto hardlink_request = pkgapply::test::fixture::rejected_request(
      incoming_plan, pkgplan::package_path::parse(hardlink.path.string()));
  bool hardlink_without_payload_rejected = false;
  try {
    static_cast<void>(rejected_store.publish_incoming(
        admitted_attempt, admitted_plan, hardlink_request, archive.image()));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    hardlink_without_payload_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::source_unavailable;
  }
  require(hardlink_without_payload_rejected,
          "hard-link rejected object published without anchor payload authority");
  require(!rejected_store.load(
               admitted_attempt, admitted_plan, hardlink_request).has_value(),
          "failed hard-link publication left a completed rejected record");

  const auto hardlink_result = rejected_store.publish_incoming(
      admitted_attempt, admitted_plan, hardlink_request, archive.image(), *payloads);
  require(hardlink_result.record().has_value() &&
              hardlink_result.record() != regular_result.record(),
          "hard-link rejected record did not receive a path-bound identity");
  auto loaded_hardlink = rejected_store.load(
      admitted_attempt, admitted_plan, hardlink_request);
  require(loaded_hardlink.has_value() &&
              loaded_hardlink->observation().object()->hardlink().state() ==
                  pkgapply::fact_state::known,
          "hard-link rejected record lost relation authority");
  require(loaded_hardlink->observation().object()->hardlink().value()->anchor() ==
              pkgplan::package_path::parse("usr/bin/tool"),
          "hard-link rejected record changed its anchor");
  {
    auto object = loaded_hardlink->open_regular();
    require(read_descriptor(object.descriptor()) == "abcd",
            "hard-link rejected record did not retain self-contained bytes");
  }

  const auto& symlink = image_entry(archive.image(), "usr/bin/tool-link");
  const auto symlink_request = pkgapply::test::fixture::rejected_request(
      incoming_plan, pkgplan::package_path::parse(symlink.path.string()));
  const auto symlink_result = rejected_store.publish_incoming(
      admitted_attempt, admitted_plan, symlink_request, archive.image());
  require(symlink_result.record().has_value(),
          "symbolic-link rejected record was not published");
  auto loaded_symlink = rejected_store.load(
      admitted_attempt, admitted_plan, symlink_request);
  require(loaded_symlink.has_value() &&
              loaded_symlink->observation().object()->symlink_target().value() ==
                  std::optional<std::string>("tool"),
          "symbolic-link rejected record changed its target");
  bool nonregular_rejected = false;
  try {
    static_cast<void>(loaded_symlink->open_regular());
  } catch (const pkgapply::posix::rejected_store_error& error) {
    nonregular_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::object_not_regular;
  }
  require(nonregular_rejected,
          "non-regular rejected record granted a payload descriptor");

  const auto& character = image_entry(archive.image(), "dev/tool-control");
  const auto character_request = pkgapply::test::fixture::rejected_request(
      incoming_plan, pkgplan::package_path::parse(character.path.string()));
  const auto character_result = rejected_store.publish_incoming(
      admitted_attempt, admitted_plan, character_request, archive.image());
  require(character_result.record().has_value(),
          "device rejected record was not published");
  auto loaded_character = rejected_store.load(
      admitted_attempt, admitted_plan, character_request);
  require(loaded_character.has_value() &&
              loaded_character->observation().object()->kind() ==
                  pkgapply::completed_object_kind::character_device &&
              loaded_character->observation().object()->device().value() ==
                  std::optional<pkgapply::completed_device_number>({1, 3}),
          "device rejected record lost typed metadata");

  bool foreign_plan_rejected = false;
  try {
    static_cast<void>(rejected_store.load(
        admitted_attempt, identity<pkgplan::operation_plan_identity>(99),
        regular_request));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    foreign_plan_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::binding_mismatch;
  }
  require(foreign_plan_rejected,
          "rejected store accepted another operation-plan identity");

  bool foreign_payload_rejected = false;
  try {
    static_cast<void>(rejected_store.publish_incoming(
        attempt(90), admitted_plan, regular_request, archive.image(), *payloads));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    foreign_payload_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::source_mismatch;
  }
  require(foreign_payload_rejected,
          "rejected store accepted payloads from another attempt");

  temporary_directory target_directory("libpkgapply-rejected-target");
  temporary_directory capture_directory("libpkgapply-rejected-capture");
  const std::string etc = target_directory.path() + "/etc";
  require(::mkdir(etc.c_str(), 0755) == 0,
          "cannot create old rejected target directory");
  write_file(etc + "/old.conf", "old bytes", 0644);

  auto observer = pkgapply::posix::application_target_observer::open(
      target_directory.path());
  const auto old_path = pkgplan::package_path::parse("etc/old.conf");
  const auto observations = observer.observe({old_path});
  auto capture_store = pkgapply::posix::application_capture_store::open(
      capture_directory.path(), target_directory.path());
  const auto old_attempt = attempt(22);
  const pkgapply::old_object_capture_request capture_request(
      old_path, true, true);
  require(capture_store.capture(
              old_attempt, capture_request,
              find_observation(observations, old_path)).outcome() ==
              pkgapply::backend_operation_outcome::completed,
          "old rejected source was not captured");
  auto captured = capture_store.load(
      old_attempt, capture_request,
      find_observation(observations, old_path));
  require(captured.has_value(), "captured old rejected source disappeared");

  const pkgapply::test::fixture::planning_authorities old_authorities(
      identity<pkgplan::target_system_context_identity>(70));
  const auto old_metadata = pkgapply::test::fixture::regular_object(7);
  const auto old_policy = pkgapply::test::fixture::policy_snapshot(
      old_authorities,
      pkgapply::test::fixture::path_policy(
          pkgplan::incoming_path_policy::activate(),
          pkgplan::obsolete_path_policy::remove(
              pkgplan::rejected_object_policy::stage)));
  const auto old_operation = pkgapply::test::fixture::removal_plan(
      old_authorities,
      {pkgplan::installed_ownership_claim(
          old_path, old_authorities.installed_package, old_metadata)},
      {pkgplan::target_path_observation::present(
          pkgplan::filesystem_object_fact(old_path, old_metadata))},
      old_policy);
  const auto old_request =
      pkgapply::test::fixture::rejected_request(old_operation, old_path);
  const auto old_result = rejected_store.publish_old(
      old_attempt, old_operation.identity(), old_request, *captured);
  require(old_result.record().has_value(),
          "old rejected object was not published");
  bool foreign_old_plan_rejected = false;
  try {
    static_cast<void>(rejected_store.publish_old(
        old_attempt, identity<pkgplan::operation_plan_identity>(99),
        old_request, *captured));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    foreign_old_plan_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::binding_mismatch;
  }
  require(foreign_old_plan_rejected,
          "old rejected attempt accepted another operation plan");
  require(::unlink((etc + "/old.conf").c_str()) == 0,
          "cannot remove old target after rejected publication");
  write_file(etc + "/old.conf", "new bytes", 0600);

  auto loaded_old = rejected_store.load(
      old_attempt, old_operation.identity(), old_request);
  require(loaded_old.has_value() &&
              loaded_old->source() ==
                  pkgapply::posix::rejected_object_source::old &&
              loaded_old->observation().object()->provenance() ==
                  pkgapply::object_fact_provenance::rejected_capture,
          "old rejected record lost capture authority");
  {
    auto object = loaded_old->open_regular();
    require(read_descriptor(object.descriptor()) == "old bytes",
            "old rejected record reread the mutated target");
  }
  require(rejected_store.publish_old(
              old_attempt, old_operation.identity(), old_request, *captured).record() ==
              old_result.record(),
          "old rejected exact republication changed identity");

  rejected_store.synchronize(admitted_attempt);
  rejected_store.synchronize(metadata_attempt);
  rejected_store.synchronize(old_attempt);

  const int rejected_fd = ::open(
      rejected_directory.path().c_str(),
      O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(rejected_fd >= 0,
          "cannot open rejected-store anchoring descriptor");
  auto anchored =
      pkgapply::posix::application_rejected_object_store::from_directory_fd(
          rejected_fd);
  require(::close(rejected_fd) == 0,
          "cannot close caller rejected-store descriptor");
  const std::string moved = rejected_directory.path() + "-moved";
  require(::rename(rejected_directory.path().c_str(), moved.c_str()) == 0,
          "cannot move rejected-object namespace");
  require(anchored.load(
              admitted_attempt, admitted_plan, regular_request).has_value(),
          "descriptor-anchored rejected store followed the old pathname");
  anchored.synchronize(admitted_attempt);
  require(::rename(moved.c_str(), rejected_directory.path().c_str()) == 0,
          "cannot restore rejected-object namespace pathname");

  const std::string attempt_hex = admitted_attempt.identity().string().substr(
      std::string("v1:sha256:").size());
  const auto path_digest = sha256(regular_request.path().string());
  const std::string corrupt_payload =
      rejected_directory.path() + "/rejected-v1-" + attempt_hex +
      "/incoming-v1/payload-v1-" +
      hexadecimal(path_digest.data(), path_digest.size());
  write_file(corrupt_payload, "wxyz", 0600);
  bool corruption_rejected = false;
  try {
    static_cast<void>(rejected_store.load(
        admitted_attempt, admitted_plan, regular_request));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    corruption_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::payload_mismatch;
  }
  require(corruption_rejected,
          "rejected payload corruption survived restart validation");

  const std::string old_attempt_hex = old_attempt.identity().string().substr(
      std::string("v1:sha256:").size());
  const auto old_path_digest = sha256(old_request.path().string());
  const std::string corrupt_record =
      rejected_directory.path() + "/rejected-v1-" + old_attempt_hex +
      "/old-v1/record-v1-" +
      hexadecimal(old_path_digest.data(), old_path_digest.size());
  write_file(corrupt_record, "broken", 0600);
  bool record_corruption_rejected = false;
  try {
    static_cast<void>(rejected_store.load(
        old_attempt, old_operation.identity(), old_request));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    record_corruption_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::record_invalid;
  }
  require(record_corruption_rejected,
          "malformed rejected record escaped typed restart validation");

  require(!rejected_store.load(
               attempt(120), admitted_plan, regular_request).has_value(),
          "rejected store aliased another application attempt");

  const std::string corrupt_binding =
      rejected_directory.path() + "/rejected-v1-" + attempt_hex +
      "/binding-v1";
  write_file(corrupt_binding, "broken", 0600);
  bool binding_corruption_rejected = false;
  try {
    static_cast<void>(rejected_store.load(
        admitted_attempt, admitted_plan, character_request));
  } catch (const pkgapply::posix::rejected_store_error& error) {
    binding_corruption_rejected = error.code() ==
        pkgapply::posix::rejected_store_error_code::binding_mismatch;
  }
  require(binding_corruption_rejected,
          "malformed rejected binding escaped typed restart validation");

  return 0;
}

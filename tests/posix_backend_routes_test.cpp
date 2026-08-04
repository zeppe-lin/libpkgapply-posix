// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "plan_fixture.h"

#include <libpkgapply-posix/backend.h>
#include <libpkgapply/apply.h>

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

std::array<std::uint8_t, 32> sha256(std::string_view bytes)
{
  std::array<std::uint8_t, 32> digest{};
  unsigned int size = 0;
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  require(context != nullptr, "cannot allocate route-test digest context");
  require(EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1,
          "cannot initialize route-test digest");
  require(EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1,
          "cannot update route-test digest");
  require(EVP_DigestFinal_ex(context, digest.data(), &size) == 1 &&
              size == digest.size(),
          "cannot finalize route-test digest");
  EVP_MD_CTX_free(context);
  return digest;
}

template<class Identity>
Identity application_identity(std::uint8_t seed)
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

class temporary_directory final {
public:
  explicit temporary_directory(std::string_view label)
  {
    std::array<char, 96> pattern{};
    const std::string seed = "/tmp/libpkgapply-backend-" +
        std::string(label) + "-XXXXXX";
    require(seed.size() + 1U <= pattern.size(),
            "backend route-test directory pattern is too long");
    std::memcpy(pattern.data(), seed.c_str(), seed.size() + 1U);
    char* value = ::mkdtemp(pattern.data());
    if (value == nullptr)
      throw std::runtime_error("cannot create backend route-test directory");
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

void make_directory(const std::string& path, mode_t mode = 0700)
{
  require(::mkdir(path.c_str(), mode) == 0,
          "cannot create backend route-test directory component");
}

int open_directory(const std::string& path)
{
  const int descriptor =
      ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(descriptor >= 0, "cannot open backend route-test directory");
  return descriptor;
}

void write_file(const std::string& path, std::string_view bytes, mode_t mode)
{
  const int descriptor = ::open(
      path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  require(descriptor >= 0, "cannot create backend route-test file");
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::write(
        descriptor, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    require(count > 0, "cannot write backend route-test file");
    offset += static_cast<std::size_t>(count);
  }
  require(::close(descriptor) == 0,
          "cannot close backend route-test file");
}

std::string read_file(const std::string& path)
{
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  require(descriptor >= 0, "cannot open backend route-test result");
  std::string result;
  std::array<char, 64> buffer{};
  for (;;) {
    const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR)
      continue;
    require(count >= 0, "cannot read backend route-test result");
    if (count == 0)
      break;
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  require(::close(descriptor) == 0,
          "cannot close backend route-test result");
  return result;
}

std::size_t visible_entries(const std::string& path)
{
  const std::string command = "find '" + path +
      "' -mindepth 1 -maxdepth 1 -printf x | wc -c";
  FILE* stream = ::popen(command.c_str(), "r");
  require(stream != nullptr, "cannot inspect backend route-test store");
  std::size_t value = 0;
  require(std::fscanf(stream, "%zu", &value) == 1,
          "cannot read backend route-test store count");
  require(::pclose(stream) == 0,
          "cannot close backend route-test store inspection");
  return value;
}

class fake_lease final : public pkgapply::target_mutation_lease {
public:
  fake_lease(pkgapply::mutation_lease_instance_identity identity,
             pkgapply::application_target_context_identity target,
             pkgapply::mutation_exclusion_domain_identity domain)
      : identity_(std::move(identity)), target_(std::move(target)),
        domain_(std::move(domain))
  {
  }

  const pkgapply::mutation_lease_instance_identity&
  identity() const noexcept override { return identity_; }
  const pkgapply::application_target_context_identity&
  target() const noexcept override { return target_; }
  const pkgapply::mutation_exclusion_domain_identity&
  exclusion_domain() const noexcept override { return domain_; }
  bool held() const noexcept override { return true; }

private:
  pkgapply::mutation_lease_instance_identity identity_;
  pkgapply::application_target_context_identity target_;
  pkgapply::mutation_exclusion_domain_identity domain_;
};

pkgapply::application_target_context target_context(std::uint8_t seed)
{
  return pkgapply::application_target_context::make(
      pkgapply::test::fixture::planning_identity<
          pkgplan::target_system_context_identity>(seed),
      application_identity<pkgapply::managed_target_identity>(seed + 1U),
      application_identity<pkgapply::root_view_identity>(seed + 2U),
      application_identity<pkgapply::observation_backend_identity>(seed + 3U),
      application_identity<pkgapply::mutation_backend_identity>(seed + 4U),
      application_identity<pkgapply::mutation_exclusion_domain_identity>(
          seed + 5U),
      application_identity<pkgapply::active_object_namespace_identity>(
          seed + 6U),
      application_identity<pkgapply::rejected_object_store_identity>(
          seed + 7U),
      application_identity<pkgapply::staging_namespace_identity>(seed + 8U),
      application_identity<pkgapply::journal_namespace_identity>(seed + 9U),
      application_identity<pkgapply::execution_capability_profile_identity>(
          seed + 10U));
}

pkgapply::application_execution_control execution_control()
{
  return pkgapply::application_execution_control::make(
      pkgapply::application_recovery_requirement::best_effort,
      pkgapply::application_durability_requirement::all_application_domains,
      pkgapply::application_cancellation_policy::recover_after_target_mutation);
}

pkgapply::lease_bound_state_projection state_projection(
    const fake_lease& lease,
    const pkgplan::operation_preconditions& preconditions,
    std::uint8_t evidence_seed)
{
  std::vector<pkgapply::projected_path_owners> paths;
  for (const auto& path : preconditions.paths())
    paths.emplace_back(path.path(), path.owners());
  return pkgapply::lease_bound_state_projection::make(
      lease.identity(), preconditions.installed_snapshot(),
      preconditions.ownership_inventory(),
      pkgapply::state_projection_completeness::complete,
      std::move(paths),
      application_identity<pkgapply::state_projection_evidence_identity>(
          evidence_seed));
}

pkgimage::package_entry regular_entry(
    std::string path, std::string_view bytes, mode_t mode)
{
  pkgimage::package_entry entry(
      pkgimage::package_path::parse(std::move(path)),
      pkgimage::entry_type::regular);
  entry.mode = static_cast<std::uint32_t>(mode);
  entry.uid = static_cast<std::uint64_t>(::getuid());
  entry.gid = static_cast<std::uint64_t>(::getgid());
  entry.size = static_cast<std::uint64_t>(bytes.size());
  entry.regular_content =
      pkgimage::regular_content_digest::from_sha256(sha256(bytes));
  return entry;
}

class memory_archive final : public pkgimage::package_archive {
public:
  memory_archive(std::vector<pkgimage::package_entry> entries,
                 std::vector<std::string> payloads,
                 pkgimage::complete_archive_digest archive_digest)
      : image_(std::move(entries)), payloads_(std::move(payloads)),
        receipt_(pkgimage::archive_backend_identity::parse(
                     "test/pkgimage-v1"),
                 std::move(archive_digest), image_.identity(), image_.size())
  {
    require(image_.size() == payloads_.size(),
            "backend route-test payload count mismatch");
  }

  const pkgimage::package_image& image() const noexcept override
  { return image_; }
  const pkgimage::archive_inspection_receipt&
  inspection_receipt() const noexcept override { return receipt_; }

  void replay(const pkgimage::entry_selection& selection,
              pkgimage::payload_sink& sink) const override
  {
    selection.validate(image_);
    for (const auto& entry : image_.entries()) {
      if (!selection.contains(entry.id))
        continue;
      sink.begin(entry);
      const std::string& payload =
          payloads_.at(static_cast<std::size_t>(entry.id));
      if (!payload.empty()) {
        sink.write(entry,
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

class backend_layout final {
public:
  backend_layout(std::string_view label, std::uint8_t target_seed)
      : root_(label), target_(target_context(target_seed)),
        target_path_(root_.path() + "/target")
  {
    make_directory(target_path_);
    for (const auto& name : store_names_)
      make_directory(root_.path() + "/" + std::string(name));

    std::array<int, 7> descriptors = {
        open_directory(target_path_),
        open_directory(store("journal")),
        open_directory(store("checkpoint")),
        open_directory(store("payload")),
        open_directory(store("capture")),
        open_directory(store("rejected")),
        open_directory(store("completed"))};
    backend_ = pkgapply::posix::application_posix_backend::from_directory_fds(
        target_, descriptors[0], descriptors[1], descriptors[2], descriptors[3],
        descriptors[4], descriptors[5], descriptors[6]);
    for (int descriptor : descriptors)
      require(::close(descriptor) == 0,
              "cannot close backend route-test caller descriptor");
  }

  [[nodiscard]] const pkgapply::application_target_context& target() const
  { return target_; }
  [[nodiscard]] pkgapply::posix::application_posix_backend& backend() const
  { return *backend_; }
  [[nodiscard]] const std::string& target_path() const noexcept
  { return target_path_; }
  [[nodiscard]] std::string store(std::string_view name) const
  { return root_.path() + "/" + std::string(name); }

private:
  static constexpr std::array<std::string_view, 6> store_names_ = {
      "journal", "checkpoint", "payload", "capture", "rejected", "completed"};
  temporary_directory root_;
  pkgapply::application_target_context target_;
  std::string target_path_;
  std::unique_ptr<pkgapply::posix::application_posix_backend> backend_;
};

const pkgapply::application_path_consequence&
consequence(const pkgapply::application_receipt& receipt,
            const pkgplan::package_path& path)
{
  for (const auto& value : receipt.paths()) {
    if (value.path() == path)
      return value;
  }
  throw std::runtime_error("backend route-test consequence is absent");
}

void test_regular_install()
{
  backend_layout layout("regular", 60);
  const auto authorities =
      pkgapply::test::fixture::planning_authorities(layout.target().target());
  const auto path = pkgplan::package_path::parse("tool");
  const std::string bytes = "abcd";
  const auto entry = regular_entry("tool", bytes, 0755);
  const auto digest = pkgimage::complete_archive_digest::from_sha256(
      sha256("regular-install-archive"));
  const auto plan = pkgapply::test::fixture::installation_plan(
      authorities, {entry}, {pkgplan::target_path_observation::absent(path)},
      {}, std::nullopt, digest);
  const auto request = pkgapply::installation_application_request::make(
      plan, pkgapply::test::fixture::incoming_package({entry}, digest),
      layout.target(), execution_control());
  memory_archive archive({entry}, {bytes}, digest);
  fake_lease lease(
      application_identity<pkgapply::mutation_lease_instance_identity>(80),
      layout.target().identity(), layout.target().mutation_exclusion_domain());
  const auto state = state_projection(lease, plan.preconditions(), 81);

  const auto receipt = pkgapply::apply(
      request, state, lease, layout.backend(), archive);
  require(receipt.outcome() == pkgapply::application_attempt_outcome::completed,
          "POSIX backend did not complete regular installation");
  require(read_file(layout.target_path() + "/tool") == bytes,
          "POSIX backend changed installed regular payload bytes");
  struct stat status {};
  require(::lstat((layout.target_path() + "/tool").c_str(), &status) == 0 &&
              S_ISREG(status.st_mode) && (status.st_mode & 07777) == 0755,
          "POSIX backend changed installed regular metadata");
  require(receipt.durability().status(
              pkgapply::application_durability_domain::incoming_staging) ==
              pkgapply::application_durability_status::confirmed &&
              receipt.durability().status(
                  pkgapply::application_durability_domain::active_namespace) ==
              pkgapply::application_durability_status::confirmed,
          "regular installation did not confirm payload and active durability");
  require(visible_entries(layout.store("payload")) != 0,
          "regular installation did not retain sealed payload authority");
}

void test_incoming_rejected_stage()
{
  backend_layout layout("rejected", 90);
  const auto authorities =
      pkgapply::test::fixture::planning_authorities(layout.target().target());
  const auto path = pkgplan::package_path::parse("candidate");
  const std::string bytes = "wxyz";
  const auto entry = regular_entry("candidate", bytes, 0644);
  const auto digest = pkgimage::complete_archive_digest::from_sha256(
      sha256("rejected-install-archive"));
  const auto policy = pkgapply::test::fixture::policy_snapshot(
      authorities,
      pkgapply::test::fixture::path_policy(
          pkgplan::incoming_path_policy::retain(
              pkgplan::rejected_object_policy::stage,
              pkgplan::retained_active_ownership_policy::
                  do_not_claim_operated_package)));
  const auto plan = pkgapply::test::fixture::installation_plan(
      authorities, {entry}, {pkgplan::target_path_observation::absent(path)},
      {}, policy, digest);
  const auto request = pkgapply::installation_application_request::make(
      plan, pkgapply::test::fixture::incoming_package({entry}, digest),
      layout.target(), execution_control());
  memory_archive archive({entry}, {bytes}, digest);
  fake_lease lease(
      application_identity<pkgapply::mutation_lease_instance_identity>(110),
      layout.target().identity(), layout.target().mutation_exclusion_domain());
  const auto state = state_projection(lease, plan.preconditions(), 111);

  const auto receipt = pkgapply::apply(
      request, state, lease, layout.backend(), archive);
  require(receipt.outcome() == pkgapply::application_attempt_outcome::completed,
          "POSIX backend did not complete rejected incoming application");
  struct stat status {};
  require(::lstat((layout.target_path() + "/candidate").c_str(), &status) != 0 &&
              errno == ENOENT,
          "rejected incoming object became active");
  const auto& path_result = consequence(receipt, path);
  require(path_result.requested_active() ==
              pkgplan::planned_active_outcome::remain_absent &&
              path_result.requested_rejected() ==
              pkgplan::planned_rejected_outcome::stage_incoming &&
              path_result.active_status() ==
              pkgapply::application_effect_status::completed &&
              path_result.rejected_status() ==
              pkgapply::application_effect_status::completed &&
              path_result.rejected_object().has_value() &&
              path_result.publication() ==
              pkgapply::ownership_publication_status::eligible,
          "rejected incoming consequence lost structured plan semantics");
  require(visible_entries(layout.store("payload")) != 0 &&
              visible_entries(layout.store("rejected")) != 0,
          "rejected incoming object lacks durable payload or record authority");
  require(receipt.durability().status(
              pkgapply::application_durability_domain::rejected_object_store) ==
              pkgapply::application_durability_status::confirmed,
          "rejected incoming object durability was not confirmed");
}

void test_regular_removal_with_capture()
{
  backend_layout layout("removal", 120);
  const std::string object_path = layout.target_path() + "/obsolete";
  write_file(object_path, "old!", 0644);

  const auto authorities =
      pkgapply::test::fixture::planning_authorities(layout.target().target());
  const auto path = pkgplan::package_path::parse("obsolete");
  const pkgplan::filesystem_object_metadata metadata(
      pkgplan::filesystem_object_kind::regular,
      0644,
      static_cast<std::uint64_t>(::getuid()),
      static_cast<std::uint64_t>(::getgid()));
  const auto policy = pkgapply::test::fixture::policy_snapshot(
      authorities,
      pkgapply::test::fixture::path_policy(
          pkgplan::incoming_path_policy::activate(),
          pkgplan::obsolete_path_policy::remove(
              pkgplan::rejected_object_policy::stage)));
  const auto plan = pkgapply::test::fixture::removal_plan(
      authorities,
      {pkgplan::installed_ownership_claim(
          path, authorities.installed_package, metadata)},
      {pkgplan::target_path_observation::present(
          pkgplan::filesystem_object_fact(path, metadata))},
      policy);
  const auto request = pkgapply::removal_application_request::make(
      plan, layout.target(), execution_control());
  fake_lease lease(
      application_identity<pkgapply::mutation_lease_instance_identity>(140),
      layout.target().identity(), layout.target().mutation_exclusion_domain());
  const auto state = state_projection(lease, plan.preconditions(), 141);

  const auto receipt = pkgapply::apply(
      request, state, lease, layout.backend());
  require(receipt.outcome() == pkgapply::application_attempt_outcome::completed,
          "POSIX backend did not complete regular removal");
  struct stat status {};
  require(::lstat(object_path.c_str(), &status) != 0 && errno == ENOENT,
          "POSIX backend did not remove selected regular object");
  const auto& path_result = consequence(receipt, path);
  require(path_result.requested_active() ==
              pkgplan::planned_active_outcome::remove_observed &&
              path_result.requested_rejected() ==
              pkgplan::planned_rejected_outcome::stage_old &&
              path_result.active_status() ==
              pkgapply::application_effect_status::completed &&
              path_result.rejected_status() ==
              pkgapply::application_effect_status::completed &&
              path_result.rejected_object().has_value() &&
              path_result.after().state() == pkgapply::fact_state::not_applicable,
          "regular removal consequence changed semantic truth");
  require(visible_entries(layout.store("capture")) != 0 &&
              visible_entries(layout.store("rejected")) != 0,
          "regular removal did not retain recovery and rejected authority");
  require(receipt.durability().status(
              pkgapply::application_durability_domain::recovery_staging) ==
              pkgapply::application_durability_status::confirmed &&
              receipt.durability().status(
                  pkgapply::application_durability_domain::active_namespace) ==
              pkgapply::application_durability_status::confirmed &&
              receipt.durability().status(
                  pkgapply::application_durability_domain::
                      rejected_object_store) ==
              pkgapply::application_durability_status::confirmed,
          "regular removal did not confirm recovery, active, and rejected durability");
}

} // namespace

int main()
{
  test_regular_install();
  test_incoming_rejected_stage();
  test_regular_removal_with_capture();
  return 0;
}

// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "plan_fixture.h"

#include <libpkgapply-posix/backend.h>
#include <libpkgapply/apply.h>
#include <libpkgapply/restart.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
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
  temporary_directory()
  {
    std::array<char, 80> pattern{};
    constexpr std::string_view seed = "/tmp/libpkgapply-backend-XXXXXX";
    std::memcpy(pattern.data(), seed.data(), seed.size());
    char* value = ::mkdtemp(pattern.data());
    if (value == nullptr)
      throw std::runtime_error("cannot create backend test directory");
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

void make_directory(const std::string& path)
{
  require(::mkdir(path.c_str(), 0700) == 0,
          "cannot create backend test directory component");
}

int open_directory(const std::string& path)
{
  const int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  require(fd >= 0, "cannot open backend test directory");
  return fd;
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
  bool held() const noexcept override { return held_; }
  void release() noexcept { held_ = false; }

private:
  pkgapply::mutation_lease_instance_identity identity_;
  pkgapply::application_target_context_identity target_;
  pkgapply::mutation_exclusion_domain_identity domain_;
  bool held_ = true;
};

class directory_archive final : public pkgimage::package_archive {
public:
  directory_archive(pkgimage::package_entry entry,
                    pkgimage::complete_archive_digest digest)
      : image_({std::move(entry)}),
        receipt_(pkgimage::archive_backend_identity::parse(
                     "test/pkgimage-v1"),
                 std::move(digest), image_.identity(), image_.size())
  {
  }

  const pkgimage::package_image& image() const noexcept override
  { return image_; }
  const pkgimage::archive_inspection_receipt&
  inspection_receipt() const noexcept override { return receipt_; }
  void replay(const pkgimage::entry_selection& selection,
              pkgimage::payload_sink&) const override
  {
    selection.validate(image_);
    require(selection.size() == 0,
            "directory-only backend fixture requested payload replay");
  }

private:
  pkgimage::package_image image_;
  pkgimage::archive_inspection_receipt receipt_;
};

pkgapply::application_target_context target_context()
{
  return pkgapply::application_target_context::make(
      pkgapply::test::fixture::planning_identity<
          pkgplan::target_system_context_identity>(1),
      application_identity<pkgapply::managed_target_identity>(2),
      application_identity<pkgapply::root_view_identity>(3),
      application_identity<pkgapply::observation_backend_identity>(4),
      application_identity<pkgapply::mutation_backend_identity>(5),
      application_identity<pkgapply::mutation_exclusion_domain_identity>(6),
      application_identity<pkgapply::active_object_namespace_identity>(7),
      application_identity<pkgapply::rejected_object_store_identity>(8),
      application_identity<pkgapply::staging_namespace_identity>(9),
      application_identity<pkgapply::journal_namespace_identity>(10),
      application_identity<
          pkgapply::execution_capability_profile_identity>(11));
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
    const pkgplan::operation_preconditions& preconditions)
{
  std::vector<pkgapply::projected_path_owners> paths;
  for (const auto& path : preconditions.paths())
    paths.emplace_back(path.path(), path.owners());
  return pkgapply::lease_bound_state_projection::make(
      lease.identity(), preconditions.installed_snapshot(),
      preconditions.ownership_inventory(),
      pkgapply::state_projection_completeness::complete,
      std::move(paths),
      application_identity<pkgapply::state_projection_evidence_identity>(30));
}

std::size_t visible_entries(const std::string& path)
{
  const std::string command = "find '" + path + "' -mindepth 1 -maxdepth 1 "
                              "-printf x | wc -c";
  FILE* stream = ::popen(command.c_str(), "r");
  require(stream != nullptr, "cannot inspect backend store");
  std::size_t value = 0;
  require(std::fscanf(stream, "%zu", &value) == 1,
          "cannot read backend store count");
  require(::pclose(stream) == 0, "cannot close backend store inspection");
  return value;
}

} // namespace

int main()
{
  temporary_directory root;
  const std::string target_path = root.path() + "/target";
  const std::string moved_target = root.path() + "/target-selected";
  const std::array<std::string, 6> store_names = {
      "journal", "checkpoint", "payload", "capture", "rejected", "completed"};
  make_directory(target_path);
  for (const auto& name : store_names)
    make_directory(root.path() + "/" + name);

  {
    std::array<int, 6> store_descriptors = {
        open_directory(root.path() + "/journal"),
        open_directory(root.path() + "/checkpoint"),
        open_directory(root.path() + "/payload"),
        open_directory(root.path() + "/capture"),
        open_directory(root.path() + "/rejected"),
        open_directory(root.path() + "/completed")};
    bool invalid_descriptor_rejected = false;
    try {
      static_cast<void>(
          pkgapply::posix::application_posix_backend::from_directory_fds(
              target_context(), -1, store_descriptors[0], store_descriptors[1],
              store_descriptors[2], store_descriptors[3], store_descriptors[4],
              store_descriptors[5]));
    }
    catch (const pkgapply::posix::posix_backend_error& error) {
      invalid_descriptor_rejected = error.code() ==
          pkgapply::posix::posix_backend_error_code::descriptor_invalid;
    }
    for (int descriptor : store_descriptors)
      require(::close(descriptor) == 0,
              "cannot close invalid-backend test descriptor");
    require(invalid_descriptor_rejected,
            "POSIX backend accepted an invalid target descriptor");
  }

  auto target = target_context();
  const auto authorities =
      pkgapply::test::fixture::planning_authorities(target.target());
  const auto path = pkgplan::package_path::parse("managed");
  pkgimage::package_entry entry(
      pkgimage::package_path::parse("managed"),
      pkgimage::entry_type::directory);
  entry.mode = 0750;
  entry.uid = static_cast<std::uint64_t>(::getuid());
  entry.gid = static_cast<std::uint64_t>(::getgid());
  entry.mtime = 123;
  entry.mtime_nanoseconds = 456;
  const auto digest = pkgapply::test::fixture::archive_digest();
  const auto plan = pkgapply::test::fixture::installation_plan(
      authorities, {entry}, {pkgplan::target_path_observation::absent(path)},
      {}, std::nullopt, digest);
  const auto request = pkgapply::installation_application_request::make(
      plan, pkgapply::test::fixture::incoming_package({entry}, digest),
      target, execution_control());
  directory_archive archive(entry, digest);
  fake_lease lease(
      application_identity<pkgapply::mutation_lease_instance_identity>(40),
      target.identity(), target.mutation_exclusion_domain());
  const auto state = state_projection(lease, plan.preconditions());

  std::array<int, 7> descriptors = {
      open_directory(target_path),
      open_directory(root.path() + "/journal"),
      open_directory(root.path() + "/checkpoint"),
      open_directory(root.path() + "/payload"),
      open_directory(root.path() + "/capture"),
      open_directory(root.path() + "/rejected"),
      open_directory(root.path() + "/completed")};
  auto backend = pkgapply::posix::application_posix_backend::from_directory_fds(
      target, descriptors[0], descriptors[1], descriptors[2], descriptors[3],
      descriptors[4], descriptors[5], descriptors[6]);
  for (int descriptor : descriptors)
    require(::close(descriptor) == 0, "cannot close caller backend descriptor");

  require(backend->identity() == target.mutation_backend() &&
              backend->observation_identity() == target.observation_backend() &&
              backend->capabilities() == target.capabilities(),
          "POSIX backend changed configured identities");

  bool archive_free_install_rejected = false;
  try {
    static_cast<void>(backend->begin_without_incoming_image(
        pkgapply::package_application_request(request), lease));
  }
  catch (const pkgapply::posix::posix_backend_error& error) {
    archive_free_install_rejected = error.code() ==
        pkgapply::posix::posix_backend_error_code::request_kind_mismatch;
  }
  require(archive_free_install_rejected,
          "POSIX backend opened an installation without image authority");

  pkgimage::package_entry foreign_entry(
      pkgimage::package_path::parse("foreign"),
      pkgimage::entry_type::directory);
  pkgimage::package_image foreign_image({foreign_entry});
  bool foreign_image_rejected = false;
  try {
    static_cast<void>(backend->begin_with_incoming_image(
        pkgapply::package_application_request(request), lease, foreign_image));
  }
  catch (const pkgapply::posix::posix_backend_error& error) {
    foreign_image_rejected = error.code() ==
        pkgapply::posix::posix_backend_error_code::incoming_image_mismatch;
  }
  require(foreign_image_rejected,
          "POSIX backend accepted an image outside the accepted plan");

  const auto removal_plan = pkgapply::test::fixture::removal_plan(
      authorities, {}, {});
  const auto removal_request = pkgapply::removal_application_request::make(
      removal_plan, target, execution_control());
  bool removal_image_rejected = false;
  try {
    static_cast<void>(backend->begin_with_incoming_image(
        pkgapply::package_application_request(removal_request), lease,
        archive.image()));
  }
  catch (const pkgapply::posix::posix_backend_error& error) {
    removal_image_rejected = error.code() ==
        pkgapply::posix::posix_backend_error_code::request_kind_mismatch;
  }
  require(removal_image_rejected,
          "POSIX backend granted incoming image authority to removal");

  const auto foreign_target = pkgapply::application_target_context::make(
      pkgapply::test::fixture::planning_identity<
          pkgplan::target_system_context_identity>(51),
      application_identity<pkgapply::managed_target_identity>(52),
      application_identity<pkgapply::root_view_identity>(53),
      application_identity<pkgapply::observation_backend_identity>(54),
      application_identity<pkgapply::mutation_backend_identity>(55),
      application_identity<pkgapply::mutation_exclusion_domain_identity>(56),
      application_identity<pkgapply::active_object_namespace_identity>(57),
      application_identity<pkgapply::rejected_object_store_identity>(58),
      application_identity<pkgapply::staging_namespace_identity>(59),
      application_identity<pkgapply::journal_namespace_identity>(60),
      application_identity<
          pkgapply::execution_capability_profile_identity>(61));
  const auto foreign_authorities =
      pkgapply::test::fixture::planning_authorities(foreign_target.target());
  const auto foreign_plan = pkgapply::test::fixture::installation_plan(
      foreign_authorities, {entry},
      {pkgplan::target_path_observation::absent(path)}, {}, std::nullopt,
      digest);
  const auto foreign_request = pkgapply::installation_application_request::make(
      foreign_plan, pkgapply::test::fixture::incoming_package({entry}, digest),
      foreign_target, execution_control());
  fake_lease foreign_lease(
      application_identity<pkgapply::mutation_lease_instance_identity>(62),
      foreign_target.identity(), foreign_target.mutation_exclusion_domain());
  bool foreign_target_rejected = false;
  try {
    static_cast<void>(backend->begin_with_incoming_image(
        pkgapply::package_application_request(foreign_request), foreign_lease,
        archive.image()));
  }
  catch (const pkgapply::posix::posix_backend_error& error) {
    foreign_target_rejected = error.code() ==
        pkgapply::posix::posix_backend_error_code::target_context_mismatch;
  }
  require(foreign_target_rejected,
          "POSIX backend accepted another target context");

  auto first = backend->begin_with_incoming_image(
      pkgapply::package_application_request(request), lease, archive.image());
  auto second = backend->begin_with_incoming_image(
      pkgapply::package_application_request(request), lease, archive.image());
  require(first->attempt_nonce() != second->attempt_nonce(),
          "fresh POSIX transactions reused an attempt nonce");
  first.reset();
  second.reset();
  for (const auto& name : store_names)
    require(visible_entries(root.path() + "/" + name) == 0,
            "transaction construction crossed a storage boundary");
  require(visible_entries(target_path) == 0,
          "transaction construction crossed the target boundary");

  auto journal_transaction = backend->begin_with_incoming_image(
      pkgapply::package_application_request(request), lease, archive.image());
  std::vector<pkgplan::package_path> admitted_paths;
  for (const auto& expected : plan.preconditions().paths())
    admitted_paths.push_back(expected.path());
  const auto admitted = journal_transaction->observe(admitted_paths);
  require(admitted.observations().size() == admitted_paths.size(),
          "POSIX transaction did not retain admission observations");
  const auto attempt = pkgapply::application_attempt::make(
      request.identity(), target.identity(), backend->identity(),
      journal_transaction->attempt_nonce());
  const auto header = pkgapply::application_journal_header::make(
      pkgplan::operation_kind::install, request.identity(), plan.identity(),
      attempt, target.identity(), request.control().identity(), state.identity(),
      lease.identity(), backend->identity());
  const auto unpublished_journal = pkgapply::application_journal_record::make(
      header, pkgapply::application_journal_state::preparing, {}, {});
  bool missing_checkpoint_rejected = false;
  try {
    static_cast<void>(backend->resume_with_incoming_image(
        pkgapply::package_application_request(request), lease,
        unpublished_journal, archive.image()));
  }
  catch (const pkgapply::posix::posix_backend_error& error) {
    missing_checkpoint_rejected = error.code() ==
        pkgapply::posix::posix_backend_error_code::restart_checkpoint_missing;
  }
  require(missing_checkpoint_rejected,
          "POSIX backend reopened a journal without its checkpoint");
  const auto journal = journal_transaction->publish_journal(unpublished_journal);
  const auto original_nonce = journal_transaction->attempt_nonce();
  journal_transaction.reset();

  fake_lease restart_lease(
      application_identity<pkgapply::mutation_lease_instance_identity>(41),
      target.identity(), target.mutation_exclusion_domain());
  auto resumed = backend->resume_with_incoming_image(
      pkgapply::package_application_request(request), restart_lease, journal,
      archive.image());
  require(resumed->attempt_nonce() == original_nonce,
          "reopened POSIX transaction allocated another attempt nonce");
  require(resumed->resumed_journal().has_value() &&
              *resumed->resumed_journal() == journal.identity(),
          "reopened POSIX transaction lost the supplied journal identity");
  const auto checkpoint = resumed->restart_checkpoint(journal);
  require(checkpoint.journal() == journal.identity() &&
              checkpoint.admitted_observations().requested() == admitted_paths,
          "reopened POSIX transaction changed restart authority");
  resumed.reset();

  require(::rename(target_path.c_str(), moved_target.c_str()) == 0,
          "cannot move selected target root");
  make_directory(target_path);

  const auto receipt = pkgapply::apply(request, state, lease, *backend, archive);
  require(receipt.outcome() == pkgapply::application_attempt_outcome::completed,
          "POSIX backend did not complete directory installation");
  require(receipt.completed_evidence().has_value(),
          "completed POSIX application lacks completed evidence");

  struct stat status {};
  require(::lstat((moved_target + "/managed").c_str(), &status) == 0 &&
              S_ISDIR(status.st_mode),
          "descriptor-anchored backend did not mutate selected target");
  require(::lstat((target_path + "/managed").c_str(), &status) != 0 &&
              errno == ENOENT,
          "descriptor-anchored backend followed replacement pathname");
  require(visible_entries(root.path() + "/journal") != 0 &&
              visible_entries(root.path() + "/checkpoint") != 0 &&
              visible_entries(root.path() + "/completed") != 0,
          "completed application did not publish durable authorities");

  lease.release();
  bool rejected = false;
  try {
    static_cast<void>(backend->begin_with_incoming_image(
        pkgapply::package_application_request(request), lease, archive.image()));
  }
  catch (const pkgapply::posix::posix_backend_error& error) {
    rejected = error.code() ==
        pkgapply::posix::posix_backend_error_code::lease_mismatch;
  }
  require(rejected, "POSIX backend accepted a released outer lease");

  return 0;
}

// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "plan_fixture.h"

#include <libpkgapply-posix/backend.h>
#include <libpkgapply-posix/journal_store.h>
#include <libpkgapply-posix/mutation_lease.h>
#include <libpkgapply/apply.h>
#include <libpkgapply/restart.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
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


class interrupt_before_active_transaction final
    : public pkgapply::application_backend_transaction {
public:
  interrupt_before_active_transaction(
      std::unique_ptr<pkgapply::application_backend_transaction> delegate,
      bool& interrupted)
      : delegate_(std::move(delegate)), interrupted_(interrupted)
  {
  }

  const pkgapply::mutation_backend_identity&
  backend() const noexcept override { return delegate_->backend(); }
  const pkgapply::observation_backend_identity&
  observation_backend() const noexcept override
  { return delegate_->observation_backend(); }
  const pkgapply::execution_capability_profile_identity&
  capabilities() const noexcept override { return delegate_->capabilities(); }
  const pkgapply::application_target_context_identity&
  target() const noexcept override { return delegate_->target(); }
  const pkgapply::mutation_lease_instance_identity&
  lease() const noexcept override { return delegate_->lease(); }
  const pkgapply::application_attempt_nonce&
  attempt_nonce() const noexcept override { return delegate_->attempt_nonce(); }

  pkgapply::backend_observation_batch observe(
      const std::vector<pkgplan::package_path>& paths) override
  { return delegate_->observe(paths); }

  std::unique_ptr<pkgapply::incoming_payload_stage> begin_payload_stage(
      const pkgimage::package_image& image,
      const pkgimage::entry_selection& selection) override
  { return delegate_->begin_payload_stage(image, selection); }

  pkgapply::old_object_capture_result capture_old(
      const pkgapply::old_object_capture_request& request) override
  { return delegate_->capture_old(request); }

  pkgapply::backend_operation_result execute_active(
      const pkgapply::backend_active_effect_request&) override
  {
    interrupted_ = true;
    throw std::runtime_error("injected POSIX active interruption");
  }

  pkgapply::rejected_object_publication_result execute_rejected(
      const pkgapply::backend_rejected_effect_request& request) override
  { return delegate_->execute_rejected(request); }

  pkgapply::completed_evidence_publication_result publish_completed_evidence(
      const pkgapply::completed_application_evidence& evidence) override
  { return delegate_->publish_completed_evidence(evidence); }

  pkgapply::backend_operation_result recover(
      const pkgplan::package_path& path) override
  { return delegate_->recover(path); }

  pkgapply::application_durability_fact synchronize(
      pkgapply::application_durability_domain domain) override
  { return delegate_->synchronize(domain); }

private:
  std::unique_ptr<pkgapply::application_backend_transaction> delegate_;
  bool& interrupted_;
};

class interrupt_before_active_backend final : public pkgapply::application_backend {
public:
  interrupt_before_active_backend(pkgapply::application_backend& delegate,
                                  bool& interrupted)
      : delegate_(delegate), interrupted_(interrupted)
  {
  }

  const pkgapply::mutation_backend_identity& identity() const noexcept override
  { return delegate_.identity(); }
  const pkgapply::observation_backend_identity&
  observation_identity() const noexcept override
  { return delegate_.observation_identity(); }
  const pkgapply::execution_capability_profile_identity&
  capabilities() const noexcept override { return delegate_.capabilities(); }

  std::unique_ptr<pkgapply::application_backend_transaction>
  begin_with_incoming_image(
      const pkgapply::package_application_request& request,
      pkgapply::target_mutation_lease& lease,
      const pkgimage::package_image& incoming_image) override
  {
    return std::make_unique<interrupt_before_active_transaction>(
        delegate_.begin_with_incoming_image(request, lease, incoming_image),
        interrupted_);
  }

  std::unique_ptr<pkgapply::application_backend_transaction>
  begin_without_incoming_image(
      const pkgapply::package_application_request& request,
      pkgapply::target_mutation_lease& lease) override
  {
    return std::make_unique<interrupt_before_active_transaction>(
        delegate_.begin_without_incoming_image(request, lease), interrupted_);
  }

private:
  pkgapply::application_backend& delegate_;
  bool& interrupted_;
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
    const pkgapply::target_mutation_lease& lease,
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
  const std::array<std::string, 5> store_names = {
      "journal", "payload", "capture", "rejected", "completed"};
  make_directory(target_path);
  make_directory(root.path() + "/locks");
  for (const auto& name : store_names)
    make_directory(root.path() + "/" + name);

  {
    std::array<int, 4> store_descriptors = {
        open_directory(root.path() + "/payload"),
        open_directory(root.path() + "/capture"),
        open_directory(root.path() + "/rejected"),
        open_directory(root.path() + "/completed")};
    bool invalid_descriptor_rejected = false;
    try {
      static_cast<void>(
          pkgapply::posix::application_posix_backend::from_directory_fds(
              target_context(), -1, store_descriptors[0], store_descriptors[1],
              store_descriptors[2], store_descriptors[3]));
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

  auto journal_store = pkgapply::posix::application_journal_store::open(
      root.path() + "/journal");
  std::array<int, 5> descriptors = {
      open_directory(target_path),
      open_directory(root.path() + "/payload"),
      open_directory(root.path() + "/capture"),
      open_directory(root.path() + "/rejected"),
      open_directory(root.path() + "/completed")};
  auto backend = pkgapply::posix::application_posix_backend::from_directory_fds(
      target, descriptors[0], descriptors[1], descriptors[2], descriptors[3],
      descriptors[4]);
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

  auto authority_probe = backend->begin_with_incoming_image(
      pkgapply::package_application_request(request), lease, archive.image());
  bool journal_sync_rejected = false;
  try {
    static_cast<void>(authority_probe->synchronize(
        pkgapply::application_durability_domain::journal));
  }
  catch (const std::invalid_argument&) {
    journal_sync_rejected = true;
  }
  require(journal_sync_rejected,
          "mutation backend accepted semantic journal durability authority");
  authority_probe.reset();

  // Interrupt after the owner has durably committed the active intent but
  // before the POSIX actuator is invoked. Restart must discover the exact
  // declaration through the direct request locator, derive semantic replay
  // state from owner steps, reopen the same physical attempt, and recover
  // without replaying the actuator.
  const int lock_directory = open_directory(root.path() + "/locks");
  auto crash_lease = pkgapply::posix::target_mutation_lease::acquire(
      target, lock_directory);
  const auto crash_state = state_projection(*crash_lease, plan.preconditions());
  bool active_interrupted = false;
  interrupt_before_active_backend interrupting_backend(
      *backend, active_interrupted);
  bool interruption_observed = false;
  try {
    static_cast<void>(pkgapply::apply(
        request, crash_state, *crash_lease, interrupting_backend,
        *journal_store, archive));
  }
  catch (const std::runtime_error& error) {
    require(std::string_view(error.what()) ==
                "injected POSIX active interruption",
            "POSIX restart fixture caught an unrelated runtime failure");
    interruption_observed = true;
  }
  require(interruption_observed && active_interrupted,
          "POSIX restart fixture did not interrupt the active mechanism");
  const auto interrupted_declaration =
      journal_store->load_active_declaration(request.identity());
  require(interrupted_declaration.has_value(),
          "POSIX restart fixture lost the direct declaration locator");
  struct stat interrupted_status {};
  require(::lstat((target_path + "/managed").c_str(), &interrupted_status) != 0 &&
              errno == ENOENT,
          "pre-actuator interruption changed the target");

  crash_lease.reset();
  auto restart_lease = pkgapply::posix::target_mutation_lease::acquire(
      target, lock_directory);
  const auto restart_state =
      state_projection(*restart_lease, plan.preconditions());
  const auto recovered = pkgapply::resume_application(
      request, restart_state, *restart_lease, *backend, *journal_store,
      *interrupted_declaration, archive);
  require(recovered.outcome() ==
              pkgapply::application_attempt_outcome::failed_fully_recovered,
          "POSIX restart did not classify unresolved active intent as recovered");
  require(::lstat((target_path + "/managed").c_str(), &interrupted_status) != 0 &&
              errno == ENOENT,
          "POSIX restart replayed an unresolved active actuator");
  restart_lease.reset();
  require(::close(lock_directory) == 0,
          "cannot close POSIX restart lock-directory descriptor");

  require(::rename(target_path.c_str(), moved_target.c_str()) == 0,
          "cannot move selected target root");
  make_directory(target_path);

  const auto receipt = pkgapply::apply(
      request, state, lease, *backend, *journal_store, archive);
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
              visible_entries(root.path() + "/completed") != 0,
          "completed application did not publish durable authorities");
  require(!std::filesystem::exists(root.path() + "/checkpoint"),
          "generation-4 POSIX application recreated a checkpoint store");

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

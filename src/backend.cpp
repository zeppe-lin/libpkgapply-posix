// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/backend.h>

#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/completed_evidence_store.h>
#include <libpkgapply-posix/payload_stage.h>
#include <libpkgapply-posix/rejected_store.h>
#include <libpkgapply-posix/target_observer.h>
#include <libpkgapply/capture.h>
#include <libpkgapply/payload.h>
#include <libpkgapply/restart.h>

#include "active_namespace.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

namespace pkgapply::posix {
namespace {

class unique_fd final {
public:
  explicit unique_fd(int value = -1) noexcept : value_(value) {}
  unique_fd(const unique_fd&) = delete;
  unique_fd& operator=(const unique_fd&) = delete;
  unique_fd(unique_fd&& other) noexcept : value_(other.release()) {}
  unique_fd& operator=(unique_fd&& other) noexcept
  {
    if (this != &other) {
      reset();
      value_ = other.release();
    }
    return *this;
  }
  ~unique_fd() { reset(); }

  [[nodiscard]] int get() const noexcept { return value_; }
  [[nodiscard]] int release() noexcept
  {
    const int value = value_;
    value_ = -1;
    return value;
  }
  void reset(int value = -1) noexcept
  {
    if (value_ >= 0)
      static_cast<void>(::close(value_));
    value_ = value;
  }

private:
  int value_;
};

[[noreturn]] void
throw_backend(posix_backend_error_code code,
              int system_error,
              const std::string& message)
{
  throw posix_backend_error(code, system_error, message);
}

[[nodiscard]] int
duplicate_directory(int descriptor)
{
  struct stat status {};
  if (descriptor < 0 || ::fstat(descriptor, &status) != 0 ||
      !S_ISDIR(status.st_mode))
  {
    throw_backend(posix_backend_error_code::descriptor_invalid,
                  descriptor < 0 ? EBADF : errno,
                  "POSIX backend descriptor is not an open directory");
  }
#ifdef F_DUPFD_CLOEXEC
  const int duplicate = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#else
  const int duplicate = ::dup(descriptor);
  if (duplicate >= 0) {
    const int flags = ::fcntl(duplicate, F_GETFD);
    if (flags < 0 || ::fcntl(duplicate, F_SETFD, flags | FD_CLOEXEC) != 0) {
      const int saved = errno;
      static_cast<void>(::close(duplicate));
      errno = saved;
      throw_backend(posix_backend_error_code::descriptor_duplicate_failed,
                    saved,
                    "cannot make POSIX backend descriptor close-on-exec");
    }
  }
#endif
  if (duplicate < 0)
    throw_backend(posix_backend_error_code::descriptor_duplicate_failed,
                  errno, "cannot duplicate POSIX backend descriptor");
  return duplicate;
}

[[nodiscard]] application_attempt_nonce
random_nonce()
{
  application_attempt_nonce::byte_array bytes {};
  if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
    throw_backend(posix_backend_error_code::attempt_nonce_failed, 0,
                  "cannot obtain an unpredictable application attempt nonce");
  }
  return application_attempt_nonce::from_bytes(bytes);
}

template<class Function>
decltype(auto)
visit_request(const package_application_request& request, Function&& function)
{
  return std::visit(
      [&function](const auto& value) -> decltype(auto) {
        return function(value);
      },
      request.body());
}

[[nodiscard]] const pkgplan::operation_preconditions&
preconditions(const package_application_request& request)
{
  return visit_request(request, [](const auto& value) -> const auto& {
    return value.plan().preconditions();
  });
}

[[nodiscard]] old_object_capture_plan
capture_plan(const package_application_request& request)
{
  return visit_request(request, [](const auto& value) {
    return prepare_old_object_captures(value.plan(), value.control());
  });
}

[[nodiscard]] std::optional<incoming_payload_plan>
payload_plan(const package_application_request& request,
             const std::optional<pkgimage::package_image>& image)
{
  if (!image)
    return std::nullopt;
  return visit_request(request, [&image](const auto& value)
      -> std::optional<incoming_payload_plan> {
    using request_type = std::decay_t<decltype(value)>;
    if constexpr (std::is_same_v<request_type, removal_application_request>) {
      throw std::logic_error("removal request acquired incoming image authority");
    }
    else {
      return prepare_incoming_payloads(value.plan(), *image);
    }
  });
}

[[nodiscard]] std::optional<backend_rejected_effect_request>
rejected_request(const package_application_request& request,
                 const pkgplan::package_path& path)
{
  return visit_request(request, [&path](const auto& value)
      -> std::optional<backend_rejected_effect_request> {
    for (const auto& decision : value.plan().paths()) {
      if (decision.path() != path)
        continue;
      if (!decision.rejected_object())
        return std::nullopt;
      return backend_rejected_effect_request::from_plan(
          *decision.rejected_object());
    }
    return std::nullopt;
  });
}

[[nodiscard]] bool
same_rejected_request(const backend_rejected_effect_request& lhs,
                      const backend_rejected_effect_request& rhs) noexcept
{
  return lhs.path() == rhs.path() && lhs.outcome() == rhs.outcome() &&
      lhs.source_side() == rhs.source_side() && lhs.reason() == rhs.reason() &&
      lhs.release() == rhs.release() && lhs.artifact() == rhs.artifact() &&
      lhs.artifact_manifest() == rhs.artifact_manifest() &&
      lhs.image() == rhs.image() &&
      lhs.incoming_entry() == rhs.incoming_entry() &&
      lhs.installed_package() == rhs.installed_package() &&
      lhs.installed_control() == rhs.installed_control() &&
      lhs.observations() == rhs.observations();
}

[[nodiscard]] bool
same_observation(const application_path_observation& lhs,
                 const application_path_observation& rhs) noexcept
{
  return lhs.path() == rhs.path() && lhs.state() == rhs.state() &&
      lhs.object() == rhs.object();
}

[[nodiscard]] std::vector<pkgplan::package_path>
precondition_paths(const package_application_request& request)
{
  std::vector<pkgplan::package_path> result;
  for (const auto& value : preconditions(request).paths())
    result.push_back(value.path());
  return result;
}

struct active_authority final {
  pkgplan::planned_active_outcome outcome;
  std::optional<pkgimage::entry_id> incoming_entry;
};

[[nodiscard]] std::optional<active_authority>
active_authority_for(const package_application_request& request,
                     const pkgplan::package_path& path)
{
  return visit_request(request, [&path](const auto& value)
      -> std::optional<active_authority> {
    for (const auto& decision : value.plan().paths()) {
      if (decision.path() != path)
        continue;
      using decision_type = std::decay_t<decltype(decision)>;
      if constexpr (std::is_same_v<decision_type,
                                   pkgplan::removal_path_decision>)
        return active_authority{decision.active(), std::nullopt};
      else
        return active_authority{decision.active(), decision.incoming_entry()};
    }
    return std::nullopt;
  });
}

[[nodiscard]] const old_object_capture_request*
find_capture_request(const old_object_capture_plan& plan,
                     const pkgplan::package_path& path) noexcept
{
  return plan.find(path);
}

[[nodiscard]] bool
changes_target(pkgplan::planned_active_outcome outcome,
               backend_operation_outcome result) noexcept
{
  if (result != backend_operation_outcome::completed)
    return false;
  return outcome == pkgplan::planned_active_outcome::activate_incoming ||
      outcome == pkgplan::planned_active_outcome::remove_observed ||
      outcome == pkgplan::planned_active_outcome::remove_directory_if_empty;
}

void
append_evidence(std::vector<application_backend_evidence_identity>& target,
                const std::vector<application_backend_evidence_identity>& source)
{
  target.insert(target.end(), source.begin(), source.end());
  std::sort(target.begin(), target.end());
  target.erase(std::unique(target.begin(), target.end()), target.end());
}

[[nodiscard]] std::size_t
durability_index(application_durability_domain domain)
{
  const auto value = static_cast<std::uint8_t>(domain);
  if (value < 1 || value > 6)
    throw std::invalid_argument("invalid application durability domain");
  return static_cast<std::size_t>(value - 1U);
}

void
validate_backend_binding(const application_target_context& configured,
                         const package_application_request& request,
                         const target_mutation_lease& lease)
{
  if (request.target().identity() != configured.identity() ||
      request.target().mutation_backend() != configured.mutation_backend() ||
      request.target().observation_backend() != configured.observation_backend() ||
      request.target().capabilities() != configured.capabilities())
  {
    throw_backend(posix_backend_error_code::target_context_mismatch, EINVAL,
                  "application request names another POSIX backend context");
  }
  if (!lease.held() || lease.target() != configured.identity() ||
      lease.exclusion_domain() != configured.mutation_exclusion_domain())
  {
    throw_backend(posix_backend_error_code::lease_mismatch, EINVAL,
                  "application lease does not protect the configured target");
  }
}

void
validate_incoming_binding(const package_application_request& request,
                          const pkgimage::package_image& image)
{
  if (request.kind() == pkgplan::operation_kind::remove)
    throw_backend(posix_backend_error_code::request_kind_mismatch, EINVAL,
                  "removal request cannot acquire incoming image authority");
  const auto& incoming = preconditions(request).incoming_archive();
  if (!incoming || incoming->image() != image.identity())
    throw_backend(posix_backend_error_code::incoming_image_mismatch, EINVAL,
                  "incoming image does not match the accepted plan");
}

void
validate_without_incoming(const package_application_request& request)
{
  if (request.kind() != pkgplan::operation_kind::remove ||
      preconditions(request).incoming_archive())
  {
    throw_backend(posix_backend_error_code::request_kind_mismatch, EINVAL,
                  "incoming operation cannot begin without image authority");
  }
}

void
validate_restart_view(const application_target_context& configured,
                      const package_application_request& request,
                      const application_restart_view& restart)
{
  const auto& attempt = restart.attempt();
  if (attempt.request() != request.identity() ||
      attempt.target() != configured.identity() ||
      attempt.backend() != configured.mutation_backend())
  {
    throw_backend(posix_backend_error_code::restart_authority_mismatch,
                  EINVAL,
                  "owner restart view does not belong to the exact application request");
  }
}

class posix_backend_transaction;

[[nodiscard]] bool
same_selection(const pkgimage::entry_selection& lhs,
               const pkgimage::entry_selection& rhs,
               const pkgimage::package_image& image)
{
  if (lhs.size() != rhs.size())
    return false;
  lhs.validate(image);
  rhs.validate(image);
  for (const auto& entry : image.entries())
    if (lhs.contains(entry.id) != rhs.contains(entry.id))
      return false;
  return true;
}

class tracked_payload_stage final : public incoming_payload_stage {
public:
  tracked_payload_stage(posix_backend_transaction& owner,
                        pkgimage::package_image image,
                        pkgimage::entry_selection selection,
                        std::unique_ptr<application_payload_stage> stage);
  ~tracked_payload_stage() override = default;

  void begin(const pkgimage::package_entry& entry) override;
  void write(const pkgimage::package_entry& entry,
             const std::byte* data,
             std::size_t size) override;
  void end(const pkgimage::package_entry& entry) override;
  [[nodiscard]] backend_operation_result seal() override;
  void abandon() noexcept override;
  [[nodiscard]] bool sealed() const noexcept override;

private:
  posix_backend_transaction* owner_;
  pkgimage::package_image image_;
  pkgimage::entry_selection selection_;
  std::unique_ptr<application_payload_stage> stage_;
};

class posix_backend_transaction final : public application_backend_transaction {
public:
  posix_backend_transaction(
      application_target_context configured,
      package_application_request request,
      target_mutation_lease& lease,
      std::optional<pkgimage::package_image> incoming_image,
      application_attempt attempt,
      int target_root_fd,
      int payload_store_fd,
      int capture_store_fd,
      int rejected_store_fd,
      int completed_evidence_store_fd,
      const application_restart_view* restart = nullptr)
      : configured_(std::move(configured)), request_(std::move(request)),
        lease_(&lease), lease_identity_(lease.identity()),
        incoming_image_(std::move(incoming_image)), attempt_(std::move(attempt)),
        target_root_(duplicate_directory(target_root_fd)),
        observer_(application_target_observer::from_directory_fd(target_root_.get())),
        payload_store_(application_payload_store::from_directory_fd(payload_store_fd)),
        capture_store_(application_capture_store::from_directory_fds(
            capture_store_fd, target_root_.get())),
        rejected_store_(application_rejected_object_store::from_directory_fd(
            rejected_store_fd)),
        completed_store_(completed_application_evidence_store::from_directory_fd(
            completed_evidence_store_fd)),
        capture_plan_(capture_plan(request_)),
        payload_plan_(payload_plan(request_, incoming_image_))
  {
    durability_.fill(application_durability_status::not_attempted);
    if (restart != nullptr)
      load_restart(*restart);
  }

  [[nodiscard]] const mutation_backend_identity&
  backend() const noexcept override
  { return configured_.mutation_backend(); }
  [[nodiscard]] const observation_backend_identity&
  observation_backend() const noexcept override
  { return configured_.observation_backend(); }
  [[nodiscard]] const execution_capability_profile_identity&
  capabilities() const noexcept override
  { return configured_.capabilities(); }
  [[nodiscard]] const application_target_context_identity&
  target() const noexcept override
  { return configured_.identity(); }
  [[nodiscard]] const mutation_lease_instance_identity&
  lease() const noexcept override
  { return lease_identity_; }
  [[nodiscard]] const application_attempt_nonce&
  attempt_nonce() const noexcept override
  { return attempt_.nonce(); }

  [[nodiscard]] backend_observation_batch observe(
      const std::vector<pkgplan::package_path>& paths) override
  {
    ensure_live_lease();
    std::vector<target_hardlink_expectation> hardlinks;
    if (incoming_image_) {
      for (const auto& entry : incoming_image_->entries()) {
        if (entry.type != pkgimage::entry_type::hardlink ||
            !entry.hardlink_target)
          continue;
        const pkgplan::package_path path =
            pkgplan::package_path::parse(entry.path.string());
        if (std::find(paths.begin(), paths.end(), path) != paths.end()) {
          hardlinks.emplace_back(
              path, pkgplan::package_path::parse(
                        entry.hardlink_target->string()));
        }
      }
    }
    backend_observation_batch result = observer_.observe(paths, hardlinks);
    append_evidence(backend_evidence_, result.evidence());
    if (!admitted_)
      admitted_ = result;
    return result;
  }

  [[nodiscard]] std::unique_ptr<incoming_payload_stage>
  begin_payload_stage(const pkgimage::package_image& image,
                      const pkgimage::entry_selection& selection) override
  {
    ensure_live_lease();
    if (!incoming_image_ || image.identity() != incoming_image_->identity() ||
        !payload_plan_ || !same_selection(
            selection, payload_plan_->selection(), image))
    {
      throw std::invalid_argument(
          "payload stage does not match transaction incoming authority");
    }
    if (sealed_payloads_)
      throw std::logic_error("transaction payloads are already sealed");
    auto stage = payload_store_.begin(attempt_, image, selection);
    return std::make_unique<tracked_payload_stage>(
        *this, image, selection, std::move(stage));
  }

  [[nodiscard]] old_object_capture_result capture_old(
      const old_object_capture_request& request) override
  {
    ensure_live_lease();
    const auto existing = std::find_if(
        captures_.begin(), captures_.end(),
        [&request](const auto& value) {
          return value.result().captured().path() == request.path();
        });
    if (existing != captures_.end())
      return existing->result();
    const auto* expected = find_capture_request(capture_plan_, request.path());
    if (expected == nullptr ||
        expected->for_rejected_object() != request.for_rejected_object() ||
        expected->for_recovery() != request.for_recovery())
    {
      throw std::invalid_argument("capture request is absent from the frozen plan");
    }
    const auto* observed = admitted_observation(request.path());
    if (observed == nullptr)
      throw std::logic_error("capture requested before admission observation");
    old_object_capture_result result =
        capture_store_.capture(attempt_, request, *observed);
    append_evidence(backend_evidence_, result.evidence());
    if (result.outcome() == backend_operation_outcome::completed) {
      auto captured = capture_store_.load(attempt_, request, *observed);
      if (!captured)
        throw std::logic_error("completed capture cannot be reopened");
      captured_objects_.push_back(std::move(*captured));
    }
    captures_.emplace_back(result);
    return result;
  }

  [[nodiscard]] backend_operation_result execute_active(
      const backend_active_effect_request& request) override
  {
    ensure_live_lease();
    const auto expected = active_authority_for(request_, request.path());
    if (!expected || expected->outcome != request.outcome() ||
        expected->incoming_entry != request.incoming_entry())
    {
      throw std::invalid_argument("active request is absent from the frozen plan");
    }
    const auto retained = std::find_if(
        active_effects_.begin(), active_effects_.end(),
        [&request](const auto& value) { return value.path() == request.path(); });
    if (retained != active_effects_.end())
      return retained->result();

    backend_operation_result result = [&] {
      switch (request.outcome()) {
        case pkgplan::planned_active_outcome::retain_observed:
        case pkgplan::planned_active_outcome::remain_absent:
          return backend_operation_result(backend_operation_outcome::completed);
        case pkgplan::planned_active_outcome::activate_incoming:
          ensure_active_namespace();
          return active_namespace_->publish_incoming(request);
        case pkgplan::planned_active_outcome::remove_observed:
        case pkgplan::planned_active_outcome::remove_directory_if_empty:
          ensure_active_namespace();
          return active_namespace_->remove(request);
      }
      throw std::logic_error("invalid planned active outcome");
    }();
    append_evidence(backend_evidence_, result.evidence());
    active_effects_.emplace_back(request.path(), result);
    return result;
  }

  [[nodiscard]] rejected_object_publication_result execute_rejected(
      const backend_rejected_effect_request& request) override
  {
    ensure_live_lease();
    const auto expected = rejected_request(request_, request.path());
    if (!expected || !same_rejected_request(*expected, request))
    {
      throw std::invalid_argument("rejected request is absent from the frozen plan");
    }
    const auto retained = std::find_if(
        rejected_effects_.begin(), rejected_effects_.end(),
        [&request](const auto& value) { return value.path() == request.path(); });
    if (retained != rejected_effects_.end())
      return retained->result();

    rejected_object_publication_result result = [&] {
      if (request.source_side() ==
          pkgplan::rejected_object_source_side::incoming)
      {
        if (!incoming_image_)
          throw std::logic_error("incoming rejected request lacks image authority");
        const auto* entry = incoming_image_->entry(*request.incoming_entry());
        if (entry == nullptr)
          throw std::invalid_argument("incoming rejected entry is absent");
        if (entry->type == pkgimage::entry_type::regular ||
            entry->type == pkgimage::entry_type::hardlink) {
          if (!sealed_payloads_)
            throw std::logic_error(
                "incoming regular rejected object lacks sealed payloads");
          return rejected_store_.publish_incoming(
              attempt_, request_.plan(), request, *incoming_image_,
              *sealed_payloads_);
        }
        return rejected_store_.publish_incoming(
            attempt_, request_.plan(), request, *incoming_image_);
      }

      const auto captured = std::find_if(
          captured_objects_.begin(), captured_objects_.end(),
          [&request](const auto& value) {
            return value.request().path() == request.path();
          });
      if (captured == captured_objects_.end())
        throw std::logic_error("old rejected request lacks capture authority");
      return rejected_store_.publish_old(
          attempt_, request_.plan(), request, *captured);
    }();
    append_evidence(backend_evidence_, result.evidence());
    rejected_effects_.emplace_back(request.path(), result);
    return result;
  }

  [[nodiscard]] completed_evidence_publication_result
  publish_completed_evidence(
      const completed_application_evidence& evidence) override
  {
    ensure_live_lease();
    if (evidence.request() != request_.identity() ||
        evidence.plan() != request_.plan() ||
        evidence.attempt() != attempt_.identity() ||
        evidence.target() != configured_.identity())
    {
      throw std::invalid_argument(
          "completed evidence does not belong to this transaction");
    }
    // The semantic owner binds completed evidence to its journal and current
    // lease-bound state projection. This mutation provider owns neither
    // journal persistence nor semantic restart authority, so it validates only
    // the request/plan/attempt/target mechanism binding before publishing the
    // supplied owner-authored evidence unchanged.
    const auto identity = visit_request(request_, [&](const auto& value) {
      return completed_store_.publish(evidence, value);
    });
    completed_evidence_ = evidence;
    completed_evidence_publication_result result(
        backend_operation_outcome::completed, identity);
    append_evidence(backend_evidence_, result.evidence());
    return result;
  }

  [[nodiscard]] backend_operation_result recover(
      const pkgplan::package_path& path) override
  {
    ensure_live_lease();
    const auto retained = std::find_if(
        recovery_effects_.begin(), recovery_effects_.end(),
        [&path](const auto& value) { return value.path() == path; });
    if (retained != recovery_effects_.end())
      return retained->result();
    ensure_active_namespace();
    backend_operation_result result = active_namespace_->recover(path);
    append_evidence(backend_evidence_, result.evidence());
    recovery_effects_.emplace_back(path, result);
    return result;
  }

  [[nodiscard]] application_durability_fact synchronize(
      application_durability_domain domain) override
  {
    ensure_live_lease();
    application_durability_status status =
        application_durability_status::confirmed;
    switch (domain) {
      case application_durability_domain::journal:
        throw std::invalid_argument(
            "journal durability is owned by the application journal store");
      case application_durability_domain::incoming_staging:
        if (!incoming_payload_result_) {
          status = application_durability_status::not_attempted;
        } else {
          try {
            payload_store_.synchronize();
          } catch (const payload_stage_error& error) {
            if (error.code() !=
                payload_stage_error_code::stage_sync_failed) {
              throw;
            }
            status = application_durability_status::unconfirmed;
          }
        }
        break;
      case application_durability_domain::recovery_staging:
        if (captures_.empty()) {
          status = application_durability_status::not_attempted;
        } else {
          try {
            capture_store_.synchronize(attempt_);
          } catch (const capture_store_error& error) {
            if (error.code() !=
                capture_store_error_code::namespace_sync_failed) {
              throw;
            }
            status = application_durability_status::unconfirmed;
          }
        }
        break;
      case application_durability_domain::active_namespace:
        if (!active_namespace_)
          status = application_durability_status::not_attempted;
        else
          status = active_namespace_->synchronize().status();
        break;
      case application_durability_domain::rejected_object_store:
        if (rejected_effects_.empty()) {
          status = application_durability_status::not_attempted;
        } else {
          try {
            rejected_store_.synchronize(attempt_);
          } catch (const rejected_store_error& error) {
            if (error.code() !=
                rejected_store_error_code::namespace_sync_failed) {
              throw;
            }
            status = application_durability_status::unconfirmed;
          }
        }
        break;
      case application_durability_domain::completed_evidence:
        if (!completed_evidence_) {
          status = application_durability_status::not_attempted;
        } else {
          try {
            completed_store_.synchronize();
          } catch (const completed_evidence_store_error& error) {
            if (error.code() !=
                completed_evidence_store_error_code::namespace_sync_failed) {
              throw;
            }
            status = application_durability_status::unconfirmed;
          }
        }
        break;
    }
    durability_[durability_index(domain)] = status;
    application_durability_fact result(domain, status);
    auto found = std::find_if(
        synchronizations_.begin(), synchronizations_.end(),
        [domain](const auto& value) { return value.domain() == domain; });
    if (found == synchronizations_.end())
      synchronizations_.emplace_back(result);
    else
      *found = application_restart_synchronization(result);
    return result;
  }

  void retain_sealed_payloads(
      const pkgimage::package_image& image,
      const pkgimage::entry_selection& selection,
      const backend_operation_result& result)
  {
    incoming_payload_result_ = result;
    append_evidence(backend_evidence_, result.evidence());
    if (result.outcome() != backend_operation_outcome::completed)
      return;
    auto loaded = payload_store_.load(attempt_, image, selection);
    if (!loaded)
      throw std::logic_error("sealed payload stage cannot be reopened");
    sealed_payloads_ = std::move(*loaded);
  }

private:
  void ensure_live_lease() const
  {
    if (lease_ == nullptr || !lease_->held() ||
        lease_->identity() != lease_identity_ ||
        lease_->target() != configured_.identity() ||
        lease_->exclusion_domain() != configured_.mutation_exclusion_domain())
    {
      throw_backend(posix_backend_error_code::lease_mismatch, EINVAL,
                    "application transaction lost its borrowed mutation lease");
    }
  }

  [[nodiscard]] const application_path_observation* admitted_observation(
      const pkgplan::package_path& path) const noexcept
  {
    return admitted_ ? admitted_->find(path) : nullptr;
  }

  void ensure_active_namespace()
  {
    if (active_namespace_)
      return;
    if (!admitted_)
      throw std::logic_error("active namespace requires admitted observations");
    std::vector<captured_old_object> captures;
    captures.swap(captured_objects_);
    if (incoming_image_) {
      active_namespace_.emplace(detail::application_active_namespace::bind(
          target_root_.get(), attempt_, *incoming_image_,
          sealed_payloads_ ? &*sealed_payloads_ : nullptr,
          admitted_->observations(), std::move(captures)));
    }
    else {
      active_namespace_.emplace(
          detail::application_active_namespace::bind_without_incoming(
              target_root_.get(), attempt_, admitted_->observations(),
              std::move(captures)));
    }
    for (const auto& effect : active_effects_) {
      const auto authority = active_authority_for(request_, effect.path());
      if (authority && changes_target(authority->outcome,
                                      effect.result().outcome()))
      {
        active_namespace_->retain_completed_effect(
            backend_active_effect_request::make(
                effect.path(), authority->outcome, authority->incoming_entry),
            effect.result());
      }
    }
  }

  void load_restart(const application_restart_view& restart)
  {
    if (restart.attempt().identity() != attempt_.identity())
      throw_backend(posix_backend_error_code::restart_authority_mismatch,
                    EINVAL,
                    "owner restart view names another physical attempt");

    admitted_ = restart.admitted_observations();
    incoming_payload_result_ = restart.incoming_payload();
    captures_ = restart.captures();
    rejected_effects_ = restart.rejected_effects();
    active_effects_ = restart.active_effects();
    recovery_effects_ = restart.recovery_effects();
    synchronizations_ = restart.synchronizations();
    completed_evidence_ = restart.completed_evidence();
    backend_evidence_ = restart.backend_evidence();
    for (const auto& fact : restart.durability().facts())
      durability_[durability_index(fact.domain())] = fact.status();

    if (admitted_->requested() != precondition_paths(request_))
      throw_backend(posix_backend_error_code::restart_authority_mismatch,
                    EINVAL,
                    "owner restart observations do not match frozen preconditions");

    if (incoming_payload_result_ &&
        incoming_payload_result_->outcome() ==
            backend_operation_outcome::completed)
    {
      if (!incoming_image_ || !payload_plan_)
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      EINVAL,
                      "restart view claims incoming payload without image authority");
      auto payloads = payload_store_.load(
          attempt_, *incoming_image_, payload_plan_->selection());
      if (!payloads)
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      ENOENT,
                      "restart-view sealed payload authority is absent");
      sealed_payloads_ = std::move(*payloads);
    }

    for (const auto& capture : captures_) {
      if (capture.result().outcome() != backend_operation_outcome::completed)
        continue;
      const auto* request = find_capture_request(capture_plan_, capture.path());
      const auto* observed = admitted_observation(capture.path());
      if (request == nullptr || observed == nullptr)
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      EINVAL,
                      "restart-view capture is absent from frozen authority");
      auto object = capture_store_.load(attempt_, *request, *observed);
      if (!object ||
          !same_observation(object->observation(), capture.result().captured()) ||
          object->exact_recovery_possible() !=
              capture.result().exact_recovery_possible())
      {
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      ENOENT,
                      "restart-view capture cannot be revalidated");
      }
      captured_objects_.push_back(std::move(*object));
    }

    for (const auto& rejected : rejected_effects_) {
      if (rejected.result().outcome() != backend_operation_outcome::completed)
        continue;
      const auto request = rejected_request(request_, rejected.path());
      if (!request || !rejected.result().record())
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      EINVAL,
                      "restart-view rejected effect is absent from frozen authority");
      const auto object = rejected_store_.load(attempt_, request_.plan(), *request);
      if (!object || object->identity() != *rejected.result().record())
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      ENOENT,
                      "restart-view rejected object cannot be revalidated");
    }

    if (completed_evidence_) {
      const auto evidence = visit_request(request_, [&](const auto& value) {
        return completed_store_.load(completed_evidence_->identity(), value);
      });
      if (!evidence || evidence->identity() != completed_evidence_->identity())
        throw_backend(posix_backend_error_code::restart_authority_mismatch,
                      ENOENT,
                      "restart-view completed evidence cannot be revalidated");
    }

    if (!active_effects_.empty() || !recovery_effects_.empty())
      ensure_active_namespace();
  }

  application_target_context configured_;
  package_application_request request_;
  target_mutation_lease* lease_;
  mutation_lease_instance_identity lease_identity_;
  std::optional<pkgimage::package_image> incoming_image_;
  application_attempt attempt_;
  unique_fd target_root_;
  application_target_observer observer_;
  application_payload_store payload_store_;
  application_capture_store capture_store_;
  application_rejected_object_store rejected_store_;
  completed_application_evidence_store completed_store_;
  old_object_capture_plan capture_plan_;
  std::optional<incoming_payload_plan> payload_plan_;
  std::optional<backend_observation_batch> admitted_;
  std::optional<sealed_application_payloads> sealed_payloads_;
  std::vector<captured_old_object> captured_objects_;
  std::optional<detail::application_active_namespace> active_namespace_;
  std::optional<backend_operation_result> incoming_payload_result_;
  std::vector<application_restart_capture> captures_;
  std::vector<application_restart_rejected_effect> rejected_effects_;
  std::vector<application_restart_active_effect> active_effects_;
  std::vector<application_restart_recovery_effect> recovery_effects_;
  std::vector<application_restart_synchronization> synchronizations_;
  std::array<application_durability_status, 6> durability_;
  std::vector<application_backend_evidence_identity> backend_evidence_;
  std::optional<completed_application_evidence> completed_evidence_;
};

tracked_payload_stage::tracked_payload_stage(
    posix_backend_transaction& owner,
    pkgimage::package_image image,
    pkgimage::entry_selection selection,
    std::unique_ptr<application_payload_stage> stage)
    : owner_(&owner), image_(std::move(image)),
      selection_(std::move(selection)), stage_(std::move(stage))
{
  if (!stage_)
    throw std::invalid_argument("tracked payload stage requires a stage");
}

void tracked_payload_stage::begin(const pkgimage::package_entry& entry)
{ stage_->begin(entry); }
void tracked_payload_stage::write(const pkgimage::package_entry& entry,
                                  const std::byte* data,
                                  std::size_t size)
{ stage_->write(entry, data, size); }
void tracked_payload_stage::end(const pkgimage::package_entry& entry)
{ stage_->end(entry); }
backend_operation_result tracked_payload_stage::seal()
{
  backend_operation_result result = stage_->seal();
  owner_->retain_sealed_payloads(image_, selection_, result);
  return result;
}
void tracked_payload_stage::abandon() noexcept
{ stage_->abandon(); }
bool tracked_payload_stage::sealed() const noexcept
{ return stage_->sealed(); }

} // namespace

class application_posix_backend::implementation final {
public:
  implementation(application_target_context target,
                 int target_root_fd,
                 int payload_store_fd,
                 int capture_store_fd,
                 int rejected_store_fd,
                 int completed_evidence_store_fd)
      : target(std::move(target)),
        target_root(duplicate_directory(target_root_fd)),
        payload_store(duplicate_directory(payload_store_fd)),
        capture_store(duplicate_directory(capture_store_fd)),
        rejected_store(duplicate_directory(rejected_store_fd)),
        completed_evidence_store(
            duplicate_directory(completed_evidence_store_fd))
  {
  }

  application_target_context target;
  unique_fd target_root;
  unique_fd payload_store;
  unique_fd capture_store;
  unique_fd rejected_store;
  unique_fd completed_evidence_store;
};

posix_backend_error::posix_backend_error(posix_backend_error_code code,
                                         int system_error,
                                         std::string message)
    : std::runtime_error(std::move(message)), code_(code),
      system_error_(system_error)
{
}

posix_backend_error::~posix_backend_error() = default;

posix_backend_error_code posix_backend_error::code() const noexcept
{ return code_; }
int posix_backend_error::system_error() const noexcept
{ return system_error_; }

std::unique_ptr<application_posix_backend>
application_posix_backend::from_directory_fds(
    application_target_context target,
    int target_root_fd,
    int payload_store_fd,
    int capture_store_fd,
    int rejected_store_fd,
    int completed_evidence_store_fd)
{
  return std::unique_ptr<application_posix_backend>(
      new application_posix_backend(std::make_unique<implementation>(
          std::move(target), target_root_fd, payload_store_fd,
          capture_store_fd, rejected_store_fd, completed_evidence_store_fd)));
}

application_posix_backend::application_posix_backend(
    std::unique_ptr<implementation> state)
    : state_(std::move(state))
{
}
application_posix_backend::~application_posix_backend() = default;

const mutation_backend_identity&
application_posix_backend::identity() const noexcept
{ return state_->target.mutation_backend(); }
const observation_backend_identity&
application_posix_backend::observation_identity() const noexcept
{ return state_->target.observation_backend(); }
const execution_capability_profile_identity&
application_posix_backend::capabilities() const noexcept
{ return state_->target.capabilities(); }

std::unique_ptr<application_backend_transaction>
application_posix_backend::begin_with_incoming_image(
    const package_application_request& request,
    target_mutation_lease& lease,
    const pkgimage::package_image& incoming_image)
{
  validate_backend_binding(state_->target, request, lease);
  validate_incoming_binding(request, incoming_image);
  application_attempt attempt = application_attempt::make(
      request.identity(), state_->target.identity(), identity(), random_nonce());
  return std::make_unique<posix_backend_transaction>(
      state_->target, request, lease,
      std::optional<pkgimage::package_image>(incoming_image),
      std::move(attempt), state_->target_root.get(), state_->payload_store.get(),
      state_->capture_store.get(), state_->rejected_store.get(),
      state_->completed_evidence_store.get());
}

std::unique_ptr<application_backend_transaction>
application_posix_backend::begin_without_incoming_image(
    const package_application_request& request,
    target_mutation_lease& lease)
{
  validate_backend_binding(state_->target, request, lease);
  validate_without_incoming(request);
  application_attempt attempt = application_attempt::make(
      request.identity(), state_->target.identity(), identity(), random_nonce());
  return std::make_unique<posix_backend_transaction>(
      state_->target, request, lease, std::nullopt, std::move(attempt),
      state_->target_root.get(), state_->payload_store.get(),
      state_->capture_store.get(), state_->rejected_store.get(),
      state_->completed_evidence_store.get());
}

std::unique_ptr<application_backend_transaction>
application_posix_backend::resume_with_incoming_image(
    const package_application_request& request,
    target_mutation_lease& lease,
    const application_restart_view& restart,
    const pkgimage::package_image& incoming_image)
{
  validate_backend_binding(state_->target, request, lease);
  validate_incoming_binding(request, incoming_image);
  validate_restart_view(state_->target, request, restart);
  return std::make_unique<posix_backend_transaction>(
      state_->target, request, lease,
      std::optional<pkgimage::package_image>(incoming_image),
      restart.attempt(), state_->target_root.get(), state_->payload_store.get(),
      state_->capture_store.get(), state_->rejected_store.get(),
      state_->completed_evidence_store.get(), &restart);
}

std::unique_ptr<application_backend_transaction>
application_posix_backend::resume_without_incoming_image(
    const package_application_request& request,
    target_mutation_lease& lease,
    const application_restart_view& restart)
{
  validate_backend_binding(state_->target, request, lease);
  validate_without_incoming(request);
  validate_restart_view(state_->target, request, restart);
  return std::make_unique<posix_backend_transaction>(
      state_->target, request, lease, std::nullopt,
      restart.attempt(), state_->target_root.get(), state_->payload_store.get(),
      state_->capture_store.get(), state_->rejected_store.get(),
      state_->completed_evidence_store.get(), &restart);
}

} // namespace pkgapply::posix

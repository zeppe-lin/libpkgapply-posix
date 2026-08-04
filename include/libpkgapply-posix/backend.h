// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <libpkgapply/backend.h>

namespace pkgapply::posix {

/*! \brief Invalid descriptor or authority binding for the POSIX backend. */
enum class posix_backend_error_code : std::uint8_t {
  descriptor_invalid = 1,
  descriptor_duplicate_failed = 2,
  target_context_mismatch = 3,
  lease_mismatch = 4,
  request_kind_mismatch = 5,
  incoming_image_mismatch = 6,
  attempt_nonce_failed = 7,
  restart_checkpoint_missing = 8,
  restart_authority_mismatch = 9,
};

/*! \brief Configuration, binding, or restart failure in backend composition. */
class posix_backend_error final : public std::runtime_error {
public:
  posix_backend_error(posix_backend_error_code code,
                      int system_error,
                      std::string message);

  [[nodiscard]] posix_backend_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;

private:
  posix_backend_error_code code_;
  int system_error_;
};

/*!
 * \brief Descriptor-anchored composition of the complete POSIX backend.
 *
 * The backend retains one exact target context and duplicates every supplied
 * directory descriptor.  Pathnames are not retained and replacing a pathname
 * after construction cannot redirect a live backend or transaction.
 */
class application_posix_backend final : public application_backend {
public:
  /*!
   * \brief Construct from already-selected directory authorities.
   *
   * Descriptors respectively identify the target root, journal store,
   * restart-checkpoint store, incoming-payload store, old-object capture
   * store, rejected-object store, and completed-evidence store.
   */
  [[nodiscard]] static std::unique_ptr<application_posix_backend>
  from_directory_fds(application_target_context target,
                     int target_root_fd,
                     int journal_store_fd,
                     int checkpoint_store_fd,
                     int payload_store_fd,
                     int capture_store_fd,
                     int rejected_store_fd,
                     int completed_evidence_store_fd);

  application_posix_backend(const application_posix_backend&) = delete;
  application_posix_backend& operator=(const application_posix_backend&) = delete;
  application_posix_backend(application_posix_backend&&) = delete;
  application_posix_backend& operator=(application_posix_backend&&) = delete;
  ~application_posix_backend() override;

  [[nodiscard]] const mutation_backend_identity&
  identity() const noexcept override;
  [[nodiscard]] const observation_backend_identity&
  observation_identity() const noexcept override;
  [[nodiscard]] const execution_capability_profile_identity&
  capabilities() const noexcept override;

  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  begin_with_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease,
      const pkgimage::package_image& incoming_image) override;

  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  begin_without_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease) override;

  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  resume_with_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease,
      const application_journal_record& journal,
      const pkgimage::package_image& incoming_image) override;

  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  resume_without_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease,
      const application_journal_record& journal) override;

private:
  class implementation;
  explicit application_posix_backend(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

} // namespace pkgapply::posix

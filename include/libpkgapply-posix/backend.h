// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file backend.h
 *  \brief Composition of the complete descriptor-anchored POSIX backend.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <libpkgapply/backend.h>

namespace pkgapply::posix {

/*! \brief Invalid descriptor or authority binding for the POSIX backend. */
enum class posix_backend_error_code : std::uint8_t {
  descriptor_invalid = 1, /*!< Supplied descriptor is not valid authority. */
  descriptor_duplicate_failed = 2, /*!< Descriptor retention failed. */
  target_context_mismatch = 3, /*!< Request names another target context. */
  lease_mismatch = 4, /*!< Lease is not bound to the retained target. */
  request_kind_mismatch = 5, /*!< Request kind contradicts begin operation. */
  incoming_image_mismatch = 6, /*!< Incoming image is not request authority. */
  attempt_nonce_failed = 7, /*!< Physical attempt nonce creation failed. */
  restart_checkpoint_missing = 8, /*!< Durable restart checkpoint is absent. */
  restart_authority_mismatch = 9, /*!< Restart material names other authority. */
};

/*! \brief Configuration, binding, or restart failure in backend composition. */
class PKGAPPLY_POSIX_API posix_backend_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed backend-composition failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   */
  posix_backend_error(posix_backend_error_code code,
                      int system_error,
                      std::string message);

  /*! \brief Destroy the polymorphic backend failure. */
  ~posix_backend_error() override;

  /*! \brief Return the stable mechanism failure class. */
  [[nodiscard]] posix_backend_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable. */
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
class PKGAPPLY_POSIX_API application_posix_backend final : public application_backend {
public:
  /*!
   * \brief Construct from already-selected directory authorities.
   *
   * Descriptors respectively identify the target root, journal store,
   * restart-checkpoint store, incoming-payload store, old-object capture
   * store, rejected-object store, and completed-evidence store.
   *
   * \param target Exact semantic target context retained by the backend.
   * \param target_root_fd Already-open managed target root.
   * \param journal_store_fd Already-open durable journal namespace.
   * \param checkpoint_store_fd Already-open restart-checkpoint namespace.
   * \param payload_store_fd Already-open private incoming-payload namespace.
   * \param capture_store_fd Already-open private old-object namespace.
   * \param rejected_store_fd Already-open rejected-object namespace.
   * \param completed_evidence_store_fd Already-open completed-evidence namespace.
   * \return Unique backend retaining duplicates of every descriptor.
   * \throws posix_backend_error If any authority cannot be retained or bound.
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
  /*! \brief Release all retained provider authorities. */
  ~application_posix_backend() override;

  /*! \brief Return stable POSIX mutation-backend identity. */
  [[nodiscard]] const mutation_backend_identity&
  identity() const noexcept override;
  /*! \brief Return stable POSIX observation-backend identity. */
  [[nodiscard]] const observation_backend_identity&
  observation_identity() const noexcept override;
  /*! \brief Return exact POSIX execution capabilities. */
  [[nodiscard]] const execution_capability_profile_identity&
  capabilities() const noexcept override;

  /*! \brief Begin one fresh installation or upgrade transaction.
   *  \param request Exact immutable application authority.
   *  \param lease Mutable borrowed caller-held mutation lease.
   *  \param incoming_image Exact admitted normalized image.
   *  \return Unique descriptor-anchored provider transaction.
   *  \throws posix_backend_error If authority or kind does not bind exactly.
   */
  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  begin_with_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease,
      const pkgimage::package_image& incoming_image) override;

  /*! \brief Begin one fresh removal transaction.
   *  \param request Exact immutable removal authority.
   *  \param lease Mutable borrowed caller-held mutation lease.
   *  \return Unique descriptor-anchored provider transaction.
   *  \throws posix_backend_error If authority or kind does not bind exactly.
   */
  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  begin_without_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease) override;

  /*! \brief Reopen one durable installation or upgrade transaction.
   *  \param request Exact immutable application authority.
   *  \param lease Mutable borrowed replacement mutation lease.
   *  \param journal Exact durable journal snapshot.
   *  \param incoming_image Exact admitted normalized image.
   *  \return Unique reopened descriptor-anchored transaction.
   *  \throws posix_backend_error If restart authority is absent or mismatched.
   */
  [[nodiscard]] std::unique_ptr<application_backend_transaction>
  resume_with_incoming_image(
      const package_application_request& request,
      target_mutation_lease& lease,
      const application_journal_record& journal,
      const pkgimage::package_image& incoming_image) override;

  /*! \brief Reopen one durable removal transaction.
   *  \param request Exact immutable removal authority.
   *  \param lease Mutable borrowed replacement mutation lease.
   *  \param journal Exact durable journal snapshot.
   *  \return Unique reopened descriptor-anchored transaction.
   *  \throws posix_backend_error If restart authority is absent or mismatched.
   */
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

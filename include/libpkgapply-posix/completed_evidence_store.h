// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file completed_evidence_store.h
 *  \brief Immutable publication and loading of completed evidence.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/completed_evidence_codec.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the completed-evidence store. */
enum class completed_evidence_store_error_code : std::uint8_t {
  directory_open_failed, /*!< Evidence directory could not be opened safely. */
  directory_invalid, /*!< Evidence authority is not a usable directory. */
  record_open_failed, /*!< Evidence record could not be opened safely. */
  record_read_failed, /*!< Evidence bytes could not be read completely. */
  record_write_failed, /*!< Evidence bytes could not be written. */
  record_sync_failed, /*!< Evidence bytes could not be synchronized. */
  record_publish_failed, /*!< Evidence could not be published atomically. */
  record_invalid, /*!< Existing evidence is malformed or contradictory. */
  record_conflict, /*!< Existing record differs from republication. */
  namespace_sync_failed, /*!< Evidence namespace could not be synchronized. */
};

/*! \brief I/O, corruption, or immutability failure in evidence storage. */
class PKGAPPLY_POSIX_API completed_evidence_store_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed durable-store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   *  \param publication_visible Whether the candidate publication may already be visible.
   */
  completed_evidence_store_error(
      completed_evidence_store_error_code code,
      int system_error,
      std::string message,
      bool publication_visible = false);

  /*! \brief Destroy the polymorphic durable-store failure. */
  ~completed_evidence_store_error() override;

  /*! \brief Return the stable mechanism failure class. */
  [[nodiscard]] completed_evidence_store_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable. */
  [[nodiscard]] int system_error() const noexcept;
  /*! \brief Return whether the candidate publication may already be visible. */
  [[nodiscard]] bool publication_visible() const noexcept;

private:
  completed_evidence_store_error_code code_;
  int system_error_;
  bool publication_visible_;
};

/*! \brief FD-anchored immutable store keyed by completed-evidence identity. */
class PKGAPPLY_POSIX_API completed_application_evidence_store final {
public:
  /*! \brief Open a caller-selected completed-evidence directory safely.
   *  \param directory Store directory pathname.
   *  \return Move-only descriptor-anchored store.
   *  \throws completed_evidence_store_error If opening or validation fails.
   */
  [[nodiscard]] static completed_application_evidence_store open(
      const std::string& directory);
  /*! \brief Duplicate and retain an already-open evidence directory.
   *  \param directory_fd Caller-selected directory descriptor.
   *  \return Move-only descriptor-anchored store.
   *  \throws completed_evidence_store_error If retention or validation fails.
   */
  [[nodiscard]] static completed_application_evidence_store from_directory_fd(
      int directory_fd);

  /*! \brief Provider objects forbid copy construction. */
  completed_application_evidence_store(
      const completed_application_evidence_store&) = delete;
  /*! \brief Provider objects forbid copy assignment. */
  completed_application_evidence_store& operator=(
      const completed_application_evidence_store&) = delete;
  /*! \brief Move one descriptor-anchored completed-evidence store. */
  completed_application_evidence_store(
      completed_application_evidence_store&& other) noexcept;
  /*! \brief Replace this store authority by move. */
  completed_application_evidence_store& operator=(
      completed_application_evidence_store&& other) noexcept;
  /*! \brief Close the retained evidence-directory descriptor. */
  ~completed_application_evidence_store();

  /*! \brief Publish one installation record against immutable request authority.
   *  \param evidence Exact completed application evidence.
   *  \param request Exact immutable installation request used for encoding.
   *  \return Canonical identity of the durably retained record.
   *  \throws completed_evidence_store_error If authority conflicts, bytes are
   *          corrupt, or publication/durability fails.
   */
  [[nodiscard]] completed_application_evidence_identity publish(
      const completed_application_evidence& evidence,
      const installation_application_request& request) const;
  /*! \brief Publish one upgrade record against immutable request authority.
   *  \param evidence Exact completed application evidence.
   *  \param request Exact immutable upgrade request used for encoding.
   *  \return Canonical identity of the durably retained record.
   *  \throws completed_evidence_store_error If authority conflicts, bytes are
   *          corrupt, or publication/durability fails.
   */
  [[nodiscard]] completed_application_evidence_identity publish(
      const completed_application_evidence& evidence,
      const upgrade_application_request& request) const;
  /*! \brief Publish one removal record against immutable request authority.
   *  \param evidence Exact completed application evidence.
   *  \param request Exact immutable removal request used for encoding.
   *  \return Canonical identity of the durably retained record.
   *  \throws completed_evidence_store_error If authority conflicts, bytes are
   *          corrupt, or publication/durability fails.
   */
  [[nodiscard]] completed_application_evidence_identity publish(
      const completed_application_evidence& evidence,
      const removal_application_request& request) const;

  /*! \brief Load one completed-evidence record for a installation request.
   *  \param identity Exact completed-evidence identity.
   *  \param request Exact immutable installation authority used for decode.
   *  \return Validated evidence, or empty when unpublished.
   *  \throws completed_evidence_store_error If retained bytes or authority are
   *          corrupt.
   */
  [[nodiscard]] std::optional<completed_application_evidence> load(
      const completed_application_evidence_identity& identity,
      const installation_application_request& request) const;
  /*! \brief Load one completed-evidence record for a upgrade request.
   *  \param identity Exact completed-evidence identity.
   *  \param request Exact immutable upgrade authority used for decode.
   *  \return Validated evidence, or empty when unpublished.
   *  \throws completed_evidence_store_error If retained bytes or authority are
   *          corrupt.
   */
  [[nodiscard]] std::optional<completed_application_evidence> load(
      const completed_application_evidence_identity& identity,
      const upgrade_application_request& request) const;
  /*! \brief Load one completed-evidence record for a removal request.
   *  \param identity Exact completed-evidence identity.
   *  \param request Exact immutable removal authority used for decode.
   *  \return Validated evidence, or empty when unpublished.
   *  \throws completed_evidence_store_error If retained bytes or authority are
   *          corrupt.
   */
  [[nodiscard]] std::optional<completed_application_evidence> load(
      const completed_application_evidence_identity& identity,
      const removal_application_request& request) const;

  /*! \brief Synchronize visible evidence records and namespace metadata.
   *  \throws completed_evidence_store_error If durability cannot be established.
   */
  void synchronize() const;

private:
  explicit completed_application_evidence_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

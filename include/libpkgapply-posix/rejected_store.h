// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file rejected_store.h
 *  \brief Immutable publication and reopening of rejected objects.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply-posix/capture_store.h>
#include <libpkgapply-posix/payload_stage.h>
#include <libpkgapply/attempt.h>
#include <libpkgapply/backend.h>
#include <libpkgimage/package_image.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the immutable POSIX rejected store. */
enum class rejected_store_error_code : std::uint8_t {
  directory_open_failed, /*!< Rejected store could not be opened safely. */
  directory_invalid, /*!< Rejected store authority is not a usable directory. */
  attempt_open_failed, /*!< Attempt namespace could not be opened. */
  attempt_invalid, /*!< Attempt namespace is structurally invalid. */
  attempt_locked, /*!< Another live writer owns this attempt namespace. */
  binding_read_failed, /*!< Existing attempt binding could not be read. */
  binding_write_failed, /*!< New attempt binding could not be written. */
  binding_mismatch, /*!< Existing attempt names different authority. */
  source_mismatch, /*!< Supplied source authority contradicts the request. */
  source_unavailable, /*!< Required incoming or captured bytes are unavailable. */
  payload_open_failed, /*!< Rejected regular payload could not be opened. */
  payload_read_failed, /*!< Source payload could not be read completely. */
  payload_write_failed, /*!< Rejected payload could not be written. */
  payload_sync_failed, /*!< Rejected payload could not be synchronized. */
  payload_mismatch, /*!< Rejected payload differs from source authority. */
  record_read_failed, /*!< Rejected record could not be read. */
  record_write_failed, /*!< Rejected record could not be written. */
  record_invalid, /*!< Rejected record is malformed or contradictory. */
  record_publish_failed, /*!< Rejected record could not be published atomically. */
  namespace_sync_failed, /*!< Rejected namespace could not be synchronized. */
  object_not_regular, /*!< Regular-byte access was requested for another type. */
};

/*! \brief POSIX rejected-object publication failure. */
class PKGAPPLY_POSIX_API rejected_store_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param path Exact logical or diagnostic path.
   *  \param message Human-readable diagnostic text.
   */
  rejected_store_error(rejected_store_error_code code,
                       int system_error,
                       std::string path,
                       std::string message);

  /*! \brief Destroy the polymorphic store failure. */
  ~rejected_store_error() override;

  /*! \brief Return the stable mechanism failure class. */
  [[nodiscard]] rejected_store_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable. */
  [[nodiscard]] int system_error() const noexcept;
  /*! \brief Return the exact diagnostic path. */
  [[nodiscard]] const std::string& path() const noexcept;

private:
  rejected_store_error_code code_;
  int system_error_;
  std::string path_;
};

/*! \brief Exact authority from which one rejected record was published. */
enum class rejected_object_source : std::uint8_t {
  incoming = 1, /*!< Record was published from admitted incoming image authority. */
  old = 2, /*!< Record was published from admitted pre-mutation capture. */
};

/*! \brief Stable read-only descriptor for one rejected regular payload. */
class PKGAPPLY_POSIX_API rejected_regular_object final {
public:
  rejected_regular_object(const rejected_regular_object&) = delete;
  rejected_regular_object& operator=(const rejected_regular_object&) = delete;
  /*! \brief Move one owned rejected-payload descriptor. */
  rejected_regular_object(rejected_regular_object&& other) noexcept;
  /*! \brief Replace this descriptor by move. */
  rejected_regular_object& operator=(rejected_regular_object&& other) noexcept;
  /*! \brief Close the retained read-only descriptor. */
  ~rejected_regular_object();

  /*! \brief Return the owned read-only descriptor. */
  [[nodiscard]] int descriptor() const noexcept;
  /*! \brief Return the verified rejected-payload byte length. */
  [[nodiscard]] std::uint64_t size() const noexcept;

private:
  friend class published_rejected_object;
  rejected_regular_object(int descriptor, std::uint64_t size) noexcept;

  int descriptor_ = -1;
  std::uint64_t size_ = 0;
};

/*! \brief One immutable rejected record reopened from canonical storage. */
class PKGAPPLY_POSIX_API published_rejected_object final {
public:
  published_rejected_object(const published_rejected_object&) = delete;
  published_rejected_object& operator=(const published_rejected_object&) = delete;
  /*! \brief Move one reopened rejected-record authority. */
  published_rejected_object(published_rejected_object&& other) noexcept;
  /*! \brief Replace this record authority by move. */
  published_rejected_object& operator=(
      published_rejected_object&& other) noexcept;
  /*! \brief Release retained record and payload descriptors. */
  ~published_rejected_object();

  /*! \brief Return the exact bound application attempt. */
  [[nodiscard]] const application_attempt& attempt() const noexcept;
  /*! \brief Return the exact accepted operation-plan identity. */
  [[nodiscard]] const pkgplan::operation_plan_identity& plan() const noexcept;
  /*! \brief Return the complete planner-derived rejected command. */
  [[nodiscard]] const backend_rejected_effect_request& request() const noexcept;
  /*! \brief Return whether bytes came from incoming or old authority. */
  [[nodiscard]] rejected_object_source source() const noexcept;
  /*! \brief Return exact observation retained by the record. */
  [[nodiscard]] const application_path_observation& observation() const noexcept;
  /*! \brief Return canonical rejected-record identity. */
  [[nodiscard]] const rejected_object_record_identity& identity() const noexcept;

  /*! \brief Open verified self-contained bytes for a regular rejected object.
   *  \return Owned read-only descriptor and verified size.
   *  \throws rejected_store_error If type, bytes, or record authority differ.
   */
  [[nodiscard]] rejected_regular_object open_regular() const;

private:
  class implementation;
  friend class application_rejected_object_store;
  explicit published_rejected_object(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief FD-anchored attempt-scoped immutable rejected-object namespace. */
class PKGAPPLY_POSIX_API application_rejected_object_store final {
public:
  /*! \brief Open a caller-selected rejected-object directory safely.
   *  \param directory Store directory pathname.
   *  \return Move-only descriptor-anchored store.
   *  \throws rejected_store_error If opening or validation fails.
   */
  [[nodiscard]] static application_rejected_object_store open(
      const std::string& directory);
  /*! \brief Duplicate and retain an already-open store directory.
   *  \param directory_fd Caller-selected directory descriptor.
   *  \return Move-only descriptor-anchored store.
   *  \throws rejected_store_error If duplication or validation fails.
   */
  [[nodiscard]] static application_rejected_object_store from_directory_fd(
      int directory_fd);

  application_rejected_object_store(
      const application_rejected_object_store&) = delete;
  application_rejected_object_store& operator=(
      const application_rejected_object_store&) = delete;
  /*! \brief Move one descriptor-anchored rejected-object store. */
  application_rejected_object_store(
      application_rejected_object_store&& other) noexcept;
  /*! \brief Replace this store authority by move. */
  application_rejected_object_store& operator=(
      application_rejected_object_store&& other) noexcept;
  /*! \brief Close the retained store-directory descriptor. */
  ~application_rejected_object_store();

  /*! \brief Publish an incoming non-regular record from exact image authority.
   *  \param attempt Exact application-attempt authority.
   *  \param plan Exact accepted operation-plan identity.
   *  \param request Complete planner-derived rejected command.
   *  \param image Exact admitted normalized package image.
   *  \return Immutable publication result and record identity when completed.
   *  \throws rejected_store_error If source, binding, record, or durability
   *          cannot be established.
   */
  [[nodiscard]] rejected_object_publication_result publish_incoming(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request,
      const pkgimage::package_image& image) const;

  /*! \brief Publish an incoming record with exact sealed payload authority.
   *  \param attempt Exact application-attempt authority.
   *  \param plan Exact accepted operation-plan identity.
   *  \param request Complete planner-derived rejected command.
   *  \param image Exact admitted normalized package image.
   *  \param payloads Sealed self-contained incoming regular bytes.
   *  \return Immutable publication result and record identity when completed.
   *  \throws rejected_store_error If source, bytes, record, or durability
   *          cannot be established.
   */
  [[nodiscard]] rejected_object_publication_result publish_incoming(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request,
      const pkgimage::package_image& image,
      const sealed_application_payloads& payloads) const;

  /*! \brief Publish one old record from pre-mutation capture authority.
   *  \param attempt Exact application-attempt authority.
   *  \param plan Exact accepted operation-plan identity.
   *  \param request Complete planner-derived rejected command.
   *  \param captured Exact immutable old-object capture.
   *  \return Immutable publication result and record identity when completed.
   *  \throws rejected_store_error If source, bytes, record, or durability
   *          cannot be established.
   */
  [[nodiscard]] rejected_object_publication_result publish_old(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request,
      const captured_old_object& captured) const;

  /*! \brief Reopen one exact immutable rejected record when published.
   *  \param attempt Exact bound application attempt.
   *  \param plan Exact accepted operation-plan identity.
   *  \param request Exact rejected command and source provenance.
   *  \return Reopened record, or empty when no record exists.
   *  \throws rejected_store_error If retained authority or bytes are corrupt.
   */
  [[nodiscard]] std::optional<published_rejected_object> load(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request) const;

  /*! \brief Synchronize one attempt's records and namespace parents.
   *  \param attempt Exact attempt namespace to synchronize.
   *  \throws rejected_store_error If durability cannot be established.
   */
  void synchronize(const application_attempt& attempt) const;

private:
  explicit application_rejected_object_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

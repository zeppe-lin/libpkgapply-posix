// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file capture_store.h
 *  \brief Private capture and reopening of admitted pre-mutation objects.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/attempt.h>
#include <libpkgapply/backend.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the private POSIX old-object store. */
enum class capture_store_error_code : std::uint8_t {
  directory_open_failed, /*!< Capture store could not be opened safely. */
  directory_invalid, /*!< Capture store authority is not a usable directory. */
  target_root_open_failed, /*!< Target root could not be opened safely. */
  target_root_invalid, /*!< Target-root authority is not a usable directory. */
  attempt_open_failed, /*!< Attempt capture namespace could not be opened. */
  attempt_invalid, /*!< Attempt capture namespace is structurally invalid. */
  attempt_locked, /*!< Another live writer owns this capture attempt. */
  binding_read_failed, /*!< Existing capture binding could not be read. */
  binding_write_failed, /*!< New capture binding could not be written. */
  binding_mismatch, /*!< Existing capture names different authority. */
  path_resolution_failed, /*!< Logical target path could not be resolved safely. */
  source_open_failed, /*!< Admitted target object could not be opened. */
  source_stat_failed, /*!< Target object metadata could not be observed stably. */
  source_read_failed, /*!< Target regular bytes could not be read completely. */
  source_changed, /*!< Target object changed during capture. */
  source_mismatch, /*!< Target object differs from admitted observation. */
  payload_open_failed, /*!< Private captured payload could not be opened. */
  payload_read_failed, /*!< Captured payload could not be read. */
  payload_write_failed, /*!< Captured payload could not be written. */
  payload_sync_failed, /*!< Captured payload could not be synchronized. */
  payload_mismatch, /*!< Captured payload does not match retained identity. */
  record_read_failed, /*!< Capture record could not be read. */
  record_write_failed, /*!< Capture record could not be written. */
  record_invalid, /*!< Capture record is malformed or contradictory. */
  record_publish_failed, /*!< Capture record could not be published atomically. */
  namespace_sync_failed, /*!< Capture namespace could not be synchronized. */
  object_not_regular, /*!< Regular-byte access was requested for another type. */
};

/*! \brief POSIX capture failure before active-target mutation authority. */
class PKGAPPLY_POSIX_API capture_store_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param path Exact logical or diagnostic path.
   *  \param message Human-readable diagnostic text.
   */
  capture_store_error(capture_store_error_code code,
                      int system_error,
                      std::string path,
                      std::string message);

  /*! \brief Destroy the polymorphic store failure. */
  ~capture_store_error() override;

  /*!
   * \brief Return the stable mechanism failure class.
  *  \return The stable mechanism failure class.
   */
  [[nodiscard]] capture_store_error_code code() const noexcept;
  /*!
   * \brief Return captured errno, or zero when inapplicable.
  *  \return Captured errno, or zero when inapplicable.
   */
  [[nodiscard]] int system_error() const noexcept;
  /*!
   * \brief Return the exact diagnostic path.
  *  \return The exact diagnostic path.
   */
  [[nodiscard]] const std::string& path() const noexcept;

private:
  capture_store_error_code code_;
  int system_error_;
  std::string path_;
};

/*! \brief Stable read-only descriptor for one captured regular object. */
class PKGAPPLY_POSIX_API captured_regular_object final {
public:
  /*! \brief Provider objects forbid copy construction. */
  captured_regular_object(const captured_regular_object&) = delete;
  /*! \brief Provider objects forbid copy assignment. */
  captured_regular_object& operator=(const captured_regular_object&) = delete;
  /*!
   * \brief Move one owned captured-object descriptor.
  *  \param other Source object whose owned resources are transferred.
   */
  captured_regular_object(captured_regular_object&& other) noexcept;
  /*!
   * \brief Replace this descriptor by move.
  *  \param other Source object whose owned resources are transferred.
  *  \return Reference to this object after taking ownership from @p other.
   */
  captured_regular_object& operator=(captured_regular_object&& other) noexcept;
  /*! \brief Close the retained read-only descriptor. */
  ~captured_regular_object();

  /*!
   * \brief Return the owned read-only descriptor.
  *  \return The owned read-only descriptor.
   */
  [[nodiscard]] int descriptor() const noexcept;
  /*!
   * \brief Return the verified captured byte length.
  *  \return The verified captured byte length.
   */
  [[nodiscard]] std::uint64_t size() const noexcept;

private:
  friend class captured_old_object;
  captured_regular_object(int descriptor, std::uint64_t size) noexcept;

  int descriptor_ = -1;
  std::uint64_t size_ = 0;
};

/*! \brief One immutable old-object capture reopened from private storage. */
class PKGAPPLY_POSIX_API captured_old_object final {
public:
  /*! \brief Provider objects forbid copy construction. */
  captured_old_object(const captured_old_object&) = delete;
  /*! \brief Provider objects forbid copy assignment. */
  captured_old_object& operator=(const captured_old_object&) = delete;
  /*!
   * \brief Move one reopened capture authority.
  *  \param other Source object whose owned resources are transferred.
   */
  captured_old_object(captured_old_object&& other) noexcept;
  /*!
   * \brief Replace this capture authority by move.
  *  \param other Source object whose owned resources are transferred.
  *  \return Reference to this object after taking ownership from @p other.
   */
  captured_old_object& operator=(captured_old_object&& other) noexcept;
  /*! \brief Release retained record and payload descriptors. */
  ~captured_old_object();

  /*!
   * \brief Return the exact bound application attempt.
  *  \return The exact bound application attempt.
   */
  [[nodiscard]] const application_attempt& attempt() const noexcept;
  /*!
   * \brief Return the exact semantic capture request.
  *  \return The exact semantic capture request.
   */
  [[nodiscard]] const old_object_capture_request& request() const noexcept;
  /*!
   * \brief Return the admitted observation retained by capture.
  *  \return The admitted observation retained by capture.
   */
  [[nodiscard]] const application_path_observation& observation() const noexcept;
  /*!
   * \brief Return whether exact prior-state recovery is possible.
  *  \return Whether exact prior-state recovery is possible.
   */
  [[nodiscard]] bool exact_recovery_possible() const noexcept;

  /*! \brief Open verified captured bytes for a regular object.
   *  \return Owned read-only descriptor and verified size.
   *  \throws capture_store_error If type, bytes, or retained authority differ.
   */
  [[nodiscard]] captured_regular_object open_regular() const;

private:
  class implementation;
  friend class application_capture_store;
  explicit captured_old_object(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief FD-anchored private store for admitted pre-mutation objects. */
class PKGAPPLY_POSIX_API application_capture_store final {
public:
  /*! \brief Open private storage and target root without final symlinks.
   *  \param directory Caller-selected private capture directory.
   *  \param target_root Caller-selected managed target root.
   *  \return Move-only descriptor-anchored capture store.
   *  \throws capture_store_error If opening or validation fails.
   */
  [[nodiscard]] static application_capture_store open(
      const std::string& directory,
      const std::string& target_root);

  /*! \brief Retain already-open storage and target-root descriptors.
   *  \param directory_fd Caller-selected capture-directory descriptor.
   *  \param target_root_fd Caller-selected target-root descriptor.
   *  \return Move-only descriptor-anchored capture store.
   *  \throws capture_store_error If duplication or validation fails.
   */
  [[nodiscard]] static application_capture_store from_directory_fds(
      int directory_fd,
      int target_root_fd);

  /*! \brief Provider objects forbid copy construction. */
  application_capture_store(const application_capture_store&) = delete;
  /*! \brief Provider objects forbid copy assignment. */
  application_capture_store& operator=(const application_capture_store&) = delete;
  /*!
   * \brief Move one descriptor-anchored capture store.
  *  \param other Source object whose owned resources are transferred.
   */
  application_capture_store(application_capture_store&& other) noexcept;
  /*!
   * \brief Replace this store authority by move.
  *  \param other Source object whose owned resources are transferred.
  *  \return Reference to this object after taking ownership from @p other.
   */
  application_capture_store& operator=(
      application_capture_store&& other) noexcept;
  /*! \brief Close retained store and target-root descriptors. */
  ~application_capture_store();

  /*! \brief Capture one admitted present object into attempt-bound storage.
   *  \param attempt Exact application-attempt authority.
   *  \param request Exact core-derived capture purpose and path.
   *  \param admitted Exact pre-mutation observation to preserve.
   *  \return Physical capture result and mechanism evidence.
   *  \throws capture_store_error If target truth, binding, bytes, or durable
   *          publication cannot be established.
   */
  [[nodiscard]] old_object_capture_result capture(
      const application_attempt& attempt,
      const old_object_capture_request& request,
      const application_path_observation& admitted) const;

  /*! \brief Reopen one exact immutable capture when published.
   *  \param attempt Exact bound application attempt.
   *  \param request Exact capture request.
   *  \param admitted Exact admitted pre-mutation observation.
   *  \return Reopened capture, or empty when no record exists.
   *  \throws capture_store_error If retained authority or bytes are corrupt.
   */
  [[nodiscard]] std::optional<captured_old_object> load(
      const application_attempt& attempt,
      const old_object_capture_request& request,
      const application_path_observation& admitted) const;

  /*! \brief Synchronize one attempt's capture namespace and parent.
   *  \param attempt Exact attempt namespace to synchronize.
   *  \throws capture_store_error If durability cannot be established.
   */
  void synchronize(const application_attempt& attempt) const;

private:
  application_capture_store(int directory_fd, int target_root_fd) noexcept;
  int directory_fd_ = -1;
  int target_root_fd_ = -1;
};

} // namespace pkgapply::posix

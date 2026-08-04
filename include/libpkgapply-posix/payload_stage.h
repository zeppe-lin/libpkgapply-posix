// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file payload_stage.h
 *  \brief Private staging and reopening of incoming regular payloads.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/backend.h>
#include <libpkgapply/attempt.h>
#include <libpkgimage/entry_selection.h>
#include <libpkgimage/package_image.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the private POSIX payload stage. */
enum class payload_stage_error_code : std::uint8_t {
  directory_open_failed, /*!< Configured store directory could not be opened. */
  directory_invalid, /*!< Store authority is not a usable directory. */
  stage_open_failed, /*!< Attempt staging directory could not be opened. */
  stage_invalid, /*!< Attempt staging authority is structurally invalid. */
  stage_locked, /*!< Another live writer owns this attempt stage. */
  binding_read_failed, /*!< Existing stage binding could not be read. */
  binding_write_failed, /*!< New stage binding could not be written. */
  binding_mismatch, /*!< Existing stage names different authority. */
  entry_unexpected, /*!< Payload sink received an unselected entry. */
  entry_order_invalid, /*!< Payload callbacks violate selected entry order. */
  entry_open_failed, /*!< Private entry file could not be opened safely. */
  entry_read_failed, /*!< Staged entry bytes could not be read. */
  entry_write_failed, /*!< Staged entry bytes could not be written. */
  entry_sync_failed, /*!< Staged entry data could not be synchronized. */
  entry_size_mismatch, /*!< Consumed byte count differs from image authority. */
  entry_content_mismatch, /*!< Consumed bytes differ from image content identity. */
  stage_sync_failed, /*!< Attempt staging namespace could not be synchronized. */
  stage_publish_failed, /*!< Sealed stage could not be published atomically. */
  stage_not_sealed, /*!< Reopening requested an incomplete attempt stage. */
};

/*! \brief POSIX staging failure before active-target mutation authority. */
class PKGAPPLY_POSIX_API payload_stage_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   */
  payload_stage_error(payload_stage_error_code code,
                      int system_error,
                      std::string message);

  /*! \brief Destroy the polymorphic store failure. */
  ~payload_stage_error() override;

  /*! \brief Return the stable mechanism failure class. */
  [[nodiscard]] payload_stage_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable. */
  [[nodiscard]] int system_error() const noexcept;

private:
  payload_stage_error_code code_;
  int system_error_;
};

/*! \brief Validated read-only descriptor for one sealed regular payload. */
class PKGAPPLY_POSIX_API staged_regular_payload final {
public:
  staged_regular_payload(const staged_regular_payload&) = delete;
  staged_regular_payload& operator=(const staged_regular_payload&) = delete;
  /*! \brief Move one owned payload descriptor. */
  staged_regular_payload(staged_regular_payload&& other) noexcept;
  /*! \brief Replace this owned descriptor by move. */
  staged_regular_payload& operator=(staged_regular_payload&& other) noexcept;
  /*! \brief Close the retained read-only descriptor. */
  ~staged_regular_payload();

  /*! \brief Return the owned read-only descriptor. */
  [[nodiscard]] int descriptor() const noexcept;
  /*! \brief Return the exact package-image entry identifier. */
  [[nodiscard]] pkgimage::entry_id entry() const noexcept;
  /*! \brief Return the verified payload byte length. */
  [[nodiscard]] std::uint64_t size() const noexcept;

private:
  friend class sealed_application_payloads;
  staged_regular_payload(int descriptor,
                         pkgimage::entry_id entry,
                         std::uint64_t size) noexcept;

  int descriptor_ = -1;
  pkgimage::entry_id entry_{};
  std::uint64_t size_ = 0;
};

/*! \brief Exact immutable payload set reopened from one sealed attempt stage. */
class PKGAPPLY_POSIX_API sealed_application_payloads final {
public:
  sealed_application_payloads(const sealed_application_payloads&) = delete;
  sealed_application_payloads& operator=(const sealed_application_payloads&) = delete;
  /*! \brief Move one reopened sealed payload authority. */
  sealed_application_payloads(sealed_application_payloads&& other) noexcept;
  /*! \brief Replace this reopened authority by move. */
  sealed_application_payloads& operator=(
      sealed_application_payloads&& other) noexcept;
  /*! \brief Release all retained attempt and payload descriptors. */
  ~sealed_application_payloads();

  /*! \brief Return the exact bound application attempt. */
  [[nodiscard]] const application_attempt& attempt() const noexcept;
  /*! \brief Return the exact physical attempt nonce. */
  [[nodiscard]] const application_attempt_nonce& attempt_nonce() const noexcept;
  /*! \brief Return the exact admitted image identity. */
  [[nodiscard]] const pkgimage::package_image_identity& image() const noexcept;
  /*! \brief Return the exact sealed regular-entry selection. */
  [[nodiscard]] const pkgimage::entry_selection& selection() const noexcept;
  /*! \brief Open one selected regular payload after revalidation.
   *  \param entry Exact selected image entry.
   *  \return Owned read-only descriptor and verified size.
   *  \throws payload_stage_error If entry is unselected, unavailable, or
   *          differs from sealed authority.
   */
  [[nodiscard]] staged_regular_payload open(pkgimage::entry_id entry) const;

private:
  class implementation;
  friend class application_payload_store;
  explicit sealed_application_payloads(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief Backend payload sink backed by one private attempt directory. */
class PKGAPPLY_POSIX_API application_payload_stage final : public incoming_payload_stage {
public:
  application_payload_stage(const application_payload_stage&) = delete;
  application_payload_stage& operator=(const application_payload_stage&) = delete;
  application_payload_stage(application_payload_stage&&) = delete;
  application_payload_stage& operator=(application_payload_stage&&) = delete;
  /*! \brief Abandon an unsealed stage and release private resources. */
  ~application_payload_stage() override;

  /*! \brief Begin consuming one exact selected regular entry.
   *  \param entry Package-image entry announced by the archive reader.
   */
  void begin(const pkgimage::package_entry& entry) override;
  /*! \brief Consume the next exact byte segment for the active entry.
   *  \param entry Package-image entry associated with the bytes.
   *  \param data First byte of the segment.
   *  \param size Number of bytes in the segment.
   */
  void write(const pkgimage::package_entry& entry,
             const std::byte* data,
             std::size_t size) override;
  /*! \brief Finish and validate the active regular entry.
   *  \param entry Package-image entry being completed.
   */
  void end(const pkgimage::package_entry& entry) override;
  /*! \brief Synchronize and atomically publish the complete private stage.
   *  \return Completed physical result with mechanism evidence.
   */
  [[nodiscard]] backend_operation_result seal() override;
  /*! \brief Discard unsealed private resources without rollback claims. */
  void abandon() noexcept override;
  /*! \brief Return whether stage publication completed successfully. */
  [[nodiscard]] bool sealed() const noexcept override;

private:
  class implementation;
  friend class application_payload_store;
  explicit application_payload_stage(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief FD-anchored namespace for private incoming regular payloads. */
class PKGAPPLY_POSIX_API application_payload_store final {
public:
  /*! \brief Open a caller-selected private payload directory safely.
   *  \param directory Store directory pathname.
   *  \return Move-only descriptor-anchored store.
   *  \throws payload_stage_error If opening or validation fails.
   */
  [[nodiscard]] static application_payload_store open(
      const std::string& directory);
  /*! \brief Duplicate and retain an already-open store directory.
   *  \param directory_fd Caller-selected directory descriptor.
   *  \return Move-only descriptor-anchored store.
   *  \throws payload_stage_error If duplication or validation fails.
   */
  [[nodiscard]] static application_payload_store from_directory_fd(
      int directory_fd);

  application_payload_store(const application_payload_store&) = delete;
  application_payload_store& operator=(const application_payload_store&) = delete;
  /*! \brief Move one descriptor-anchored payload store. */
  application_payload_store(application_payload_store&& other) noexcept;
  /*! \brief Replace this store authority by move. */
  application_payload_store& operator=(
      application_payload_store&& other) noexcept;
  /*! \brief Close the retained store-directory descriptor. */
  ~application_payload_store();

  /*! \brief Begin a private stage for one exact attempt and image selection.
   *  \param attempt Exact semantic and physical attempt authority.
   *  \param image Exact admitted normalized package image.
   *  \param selection Exact regular-entry closure to consume.
   *  \return Unique backend payload sink.
   *  \throws payload_stage_error If attempt authority cannot be created or
   *          an existing binding conflicts.
   */
  [[nodiscard]] std::unique_ptr<application_payload_stage> begin(
      const application_attempt& attempt,
      const pkgimage::package_image& image,
      const pkgimage::entry_selection& selection) const;

  /*! \brief Reopen an exact sealed stage when it exists.
   *  \param attempt Exact bound application attempt.
   *  \param image Exact admitted image authority.
   *  \param selection Exact sealed regular-entry selection.
   *  \return Reopened authority, or empty when no stage was published.
   *  \throws payload_stage_error If retained bytes or binding are corrupt.
   */
  [[nodiscard]] std::optional<sealed_application_payloads> load(
      const application_attempt& attempt,
      const pkgimage::package_image& image,
      const pkgimage::entry_selection& selection) const;

  /*! \brief Synchronize namespace directory metadata after publication.
   *  \throws payload_stage_error If directory synchronization fails.
   */
  void synchronize() const;

private:
  explicit application_payload_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

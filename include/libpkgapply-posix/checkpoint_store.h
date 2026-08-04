// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file checkpoint_store.h
 *  \brief Immutable publication and loading of restart checkpoints.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/restart_checkpoint_codec.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the FD-anchored checkpoint store. */
enum class checkpoint_store_error_code : std::uint8_t {
  directory_open_failed, /*!< Checkpoint directory could not be opened safely. */
  directory_invalid, /*!< Checkpoint authority is not a usable directory. */
  snapshot_open_failed, /*!< Checkpoint snapshot could not be opened safely. */
  snapshot_read_failed, /*!< Checkpoint bytes could not be read completely. */
  snapshot_write_failed, /*!< Checkpoint bytes could not be written. */
  snapshot_sync_failed, /*!< Checkpoint bytes could not be synchronized. */
  snapshot_publish_failed, /*!< Checkpoint could not be published atomically. */
  directory_sync_failed, /*!< Checkpoint namespace could not be synchronized. */
  snapshot_corrupt, /*!< Existing checkpoint is malformed or contradictory. */
  snapshot_conflict, /*!< Existing checkpoint differs from republication. */
};

/*! \brief I/O, corruption, or immutability failure in checkpoint storage. */
class PKGAPPLY_POSIX_API checkpoint_store_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed durable-store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   *  \param publication_visible Whether the candidate publication may already be visible.
   */
  checkpoint_store_error(
      checkpoint_store_error_code code,
      int system_error,
      std::string message,
      bool publication_visible = false);

  /*! \brief Destroy the polymorphic durable-store failure. */
  ~checkpoint_store_error() override;

  /*! \brief Return the stable mechanism failure class. */
  [[nodiscard]] checkpoint_store_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable. */
  [[nodiscard]] int system_error() const noexcept;
  /*! \brief Return whether the candidate publication may already be visible. */
  [[nodiscard]] bool publication_visible() const noexcept;

private:
  checkpoint_store_error_code code_;
  int system_error_;
  bool publication_visible_;
};

/*! \brief Immutable FD-anchored checkpoint store keyed by journal snapshot. */
class PKGAPPLY_POSIX_API application_restart_checkpoint_store final {
public:
  /*! \brief Open a caller-selected checkpoint directory safely.
   *  \param directory Store directory pathname.
   *  \return Move-only descriptor-anchored store.
   *  \throws checkpoint_store_error If opening or validation fails.
   */
  [[nodiscard]] static application_restart_checkpoint_store open(
      const std::string& directory);
  /*! \brief Duplicate and retain an already-open checkpoint directory.
   *  \param directory_fd Caller-selected directory descriptor.
   *  \return Move-only descriptor-anchored store.
   *  \throws checkpoint_store_error If duplication or validation fails.
   */
  [[nodiscard]] static application_restart_checkpoint_store from_directory_fd(
      int directory_fd);

  application_restart_checkpoint_store(
      const application_restart_checkpoint_store&) = delete;
  application_restart_checkpoint_store& operator=(
      const application_restart_checkpoint_store&) = delete;
  /*! \brief Move one descriptor-anchored checkpoint store. */
  application_restart_checkpoint_store(
      application_restart_checkpoint_store&& other) noexcept;
  /*! \brief Replace this store authority by move. */
  application_restart_checkpoint_store& operator=(
      application_restart_checkpoint_store&& other) noexcept;
  /*! \brief Close the retained checkpoint-directory descriptor. */
  ~application_restart_checkpoint_store();

  /*! \brief Publish one immutable checkpoint, accepting exact republication.
   *  \param journal Exact durable journal snapshot named by the checkpoint.
   *  \param checkpoint Exact closed semantic restart material.
   *  \return Exact checkpoint durably retained by the store.
   *  \throws checkpoint_store_error If authority conflicts, bytes are corrupt,
   *          or publication/durability fails.
   */
  [[nodiscard]] application_restart_checkpoint publish(
      const application_journal_record& journal,
      const application_restart_checkpoint& checkpoint);

  /*! \brief Load one immutable checkpoint for a installation request.
   *  \param journal Exact durable journal snapshot.
   *  \param request Exact immutable installation authority used for decode.
   *  \return Validated checkpoint, or empty when unpublished.
   *  \throws checkpoint_store_error If retained bytes or authority are corrupt.
   */
  [[nodiscard]] std::optional<application_restart_checkpoint> load(
      const application_journal_record& journal,
      const installation_application_request& request) const;
  /*! \brief Load one immutable checkpoint for a upgrade request.
   *  \param journal Exact durable journal snapshot.
   *  \param request Exact immutable upgrade authority used for decode.
   *  \return Validated checkpoint, or empty when unpublished.
   *  \throws checkpoint_store_error If retained bytes or authority are corrupt.
   */
  [[nodiscard]] std::optional<application_restart_checkpoint> load(
      const application_journal_record& journal,
      const upgrade_application_request& request) const;
  /*! \brief Load one immutable checkpoint for a removal request.
   *  \param journal Exact durable journal snapshot.
   *  \param request Exact immutable removal authority used for decode.
   *  \return Validated checkpoint, or empty when unpublished.
   *  \throws checkpoint_store_error If retained bytes or authority are corrupt.
   */
  [[nodiscard]] std::optional<application_restart_checkpoint> load(
      const application_journal_record& journal,
      const removal_application_request& request) const;

private:
  explicit application_restart_checkpoint_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

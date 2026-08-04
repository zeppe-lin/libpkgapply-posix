// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file journal_store.h
 *  \brief Atomic publication and loading of durable application journals.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/journal.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the FD-anchored journal store. */
enum class journal_store_error_code : std::uint8_t {
  directory_open_failed, /*!< Journal directory could not be opened safely. */
  directory_invalid, /*!< Journal authority is not a usable directory. */
  snapshot_open_failed, /*!< Journal snapshot could not be opened safely. */
  snapshot_read_failed, /*!< Journal bytes could not be read completely. */
  snapshot_write_failed, /*!< Replacement bytes could not be written. */
  snapshot_sync_failed, /*!< Replacement bytes could not be synchronized. */
  snapshot_rename_failed, /*!< Replacement could not become visible atomically. */
  directory_sync_failed, /*!< Journal namespace could not be synchronized. */
  snapshot_corrupt, /*!< Existing snapshot is malformed or contradictory. */
  snapshot_conflict, /*!< Candidate is not an exact or monotonic successor. */
};

/*! \brief I/O, corruption, or monotonicity failure in durable journal storage. */
class PKGAPPLY_POSIX_API journal_store_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed durable-store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   *  \param replacement_visible Whether the candidate replacement may already be visible.
   */
  journal_store_error(
      journal_store_error_code code,
      int system_error,
      std::string message,
      bool replacement_visible = false);

  /*! \brief Destroy the polymorphic durable-store failure. */
  ~journal_store_error() override;

  /*!
   * \brief Return the stable mechanism failure class.
  *  \return The stable mechanism failure class.
   */
  [[nodiscard]] journal_store_error_code code() const noexcept;
  /*!
   * \brief Return captured errno, or zero when inapplicable.
  *  \return Captured errno, or zero when inapplicable.
   */
  [[nodiscard]] int system_error() const noexcept;
  /*!
   * \brief Return whether the candidate replacement may already be visible.
  *  \return Whether the candidate replacement may already be visible.
   */
  [[nodiscard]] bool replacement_visible() const noexcept;

private:
  journal_store_error_code code_;
  int system_error_;
  bool replacement_visible_;
};

/*! \brief Atomic FD-anchored store for one snapshot per journal identity. */
class PKGAPPLY_POSIX_API application_journal_store final {
public:
  /*! \brief Open a real journal directory without a final symlink.
   *  \param directory Caller-selected journal directory.
   *  \return Move-only descriptor-anchored store.
   *  \throws journal_store_error If opening or validation fails.
   */
  [[nodiscard]] static application_journal_store open(
      const std::string& directory);

  /*! \brief Duplicate and retain an already-open journal directory.
   *  \param directory_fd Caller-selected directory descriptor.
   *  \return Move-only descriptor-anchored store.
   *  \throws journal_store_error If duplication or validation fails.
   */
  [[nodiscard]] static application_journal_store from_directory_fd(
      int directory_fd);

  /*! \brief Provider objects forbid copy construction. */
  application_journal_store(const application_journal_store&) = delete;
  /*! \brief Provider objects forbid copy assignment. */
  application_journal_store& operator=(const application_journal_store&) = delete;
  /*!
   * \brief Move one descriptor-anchored journal store.
  *  \param other Source object whose owned resources are transferred.
   */
  application_journal_store(application_journal_store&& other) noexcept;
  /*!
   * \brief Replace this store authority by move.
  *  \param other Source object whose owned resources are transferred.
  *  \return Reference to this object after taking ownership from @p other.
   */
  application_journal_store& operator=(
      application_journal_store&& other) noexcept;
  /*! \brief Close the retained journal-directory descriptor. */
  ~application_journal_store();

  /*! \brief Publish an exact or monotonic successor snapshot atomically.
   *  \param record Validated immutable journal snapshot.
   *  \return Exact snapshot durably retained by the store.
   *  \throws journal_store_error If existing bytes are corrupt, transition is
   *          non-monotonic, or publication/durability fails.
   */
  [[nodiscard]] application_journal_record publish(
      const application_journal_record& record);

  /*! \brief Load and validate the current snapshot for one journal identity.
   *  \param journal Exact application-journal identity.
   *  \return Current validated snapshot, or empty when unpublished.
   *  \throws journal_store_error If retained bytes cannot be read or decoded.
   */
  [[nodiscard]] std::optional<application_journal_record> load(
      const application_journal_identity& journal) const;

private:
  explicit application_journal_store(int directory_fd) noexcept;

  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

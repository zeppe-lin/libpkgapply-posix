// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file journal_store.h
 *  \brief Descriptor-anchored persistence for append-only application journals.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/journal_transport.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the append-only POSIX journal store. */
enum class journal_store_error_code : std::uint8_t {
  directory_open_failed = 1, /*!< Store directory could not be opened safely. */
  directory_invalid = 2, /*!< Store authority is not a usable directory. */
  namespace_open_failed = 3, /*!< Exact journal namespace could not be opened. */
  value_open_failed = 4, /*!< Exact retained value could not be opened safely. */
  value_read_failed = 5, /*!< Retained bytes could not be read completely. */
  value_write_failed = 6, /*!< Candidate bytes could not be written completely. */
  value_sync_failed = 7, /*!< Candidate bytes could not be synchronized. */
  value_publish_failed = 8, /*!< Candidate name could not be published atomically. */
  directory_sync_failed = 9, /*!< A containing namespace could not be synchronized. */
  value_corrupt = 10, /*!< Retained bytes or file type are contradictory. */
  immutable_conflict = 11, /*!< An immutable exact-name value already differs. */
  cursor_conflict = 12, /*!< Cursor compare-and-publish expectation is stale. */
  index_corrupt = 13, /*!< Direct request locator is malformed or contradictory. */
  lock_failed = 14, /*!< Cursor serialization authority could not be acquired. */
};

/*! \brief I/O, corruption, or publication failure in journal persistence. */
class PKGAPPLY_POSIX_API journal_store_error final : public std::runtime_error {
public:
  /*! \brief Construct one typed durable-store failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   *  \param publication_visible Whether candidate bytes may already be visible.
   */
  journal_store_error(journal_store_error_code code,
                      int system_error,
                      std::string message,
                      bool publication_visible = false);

  /*! \brief Destroy the polymorphic durable-store failure. */
  ~journal_store_error() override;

  /*! \brief Return the stable mechanism failure class.
   *  \return Stable mechanism failure class.
   */
  [[nodiscard]] journal_store_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable.
   *  \return Captured errno, or zero when inapplicable.
   */
  [[nodiscard]] int system_error() const noexcept;
  /*! \brief Return whether candidate bytes may already be visible.
   *  \return Whether a failed publication may already be visible.
   */
  [[nodiscard]] bool publication_visible() const noexcept;

private:
  journal_store_error_code code_;
  int system_error_;
  bool publication_visible_;
};

/*! \brief Exact-name POSIX store for one append-only semantic journal spine.
 *
 * The store persists only owner-encoded declaration, step, and cursor bytes.
 * It never decodes a complete journal snapshot, reconstructs semantic history,
 * enumerates the store directory to discover authority, or observes the target.
 */
class PKGAPPLY_POSIX_API application_journal_store final
    : public ::pkgapply::application_journal_store {
public:
  /*! \brief Open a real journal root without following its final component.
   *  \param directory Caller-selected journal-store root.
   *  \return Unique descriptor-anchored store implementation.
   *  \throws journal_store_error If opening or validation fails.
   */
  [[nodiscard]] static std::unique_ptr<application_journal_store> open(
      const std::string& directory);

  /*! \brief Duplicate and retain an already-open journal root.
   *  \param directory_fd Caller-selected directory descriptor.
   *  \return Unique descriptor-anchored store implementation.
   *  \throws journal_store_error If duplication or validation fails.
   */
  [[nodiscard]] static std::unique_ptr<application_journal_store>
  from_directory_fd(int directory_fd);

  /*! \brief Store objects forbid copy construction. */
  application_journal_store(const application_journal_store&) = delete;
  /*! \brief Store objects forbid copy assignment. */
  application_journal_store& operator=(const application_journal_store&) = delete;
  /*! \brief Store objects forbid move construction. */
  application_journal_store(application_journal_store&&) = delete;
  /*! \brief Store objects forbid move assignment. */
  application_journal_store& operator=(application_journal_store&&) = delete;
  /*! \brief Close the retained journal-root descriptor. */
  ~application_journal_store() override;

  /*! \brief Publish one immutable owner-encoded declaration.
   *  \param declaration Exact semantic declaration authority.
   *  \return The exact published declaration.
   *  \throws journal_store_error On I/O, corruption, or immutable conflict.
   */
  [[nodiscard]] application_journal_declaration publish_declaration(
      const application_journal_declaration& declaration) override;
  /*! \brief Publish one immutable sequence-addressed owner step.
   *  \param step Exact semantic step authority.
   *  \return The exact published step.
   *  \throws journal_store_error On I/O, corruption, or immutable conflict.
   */
  [[nodiscard]] application_journal_step publish_step(
      const application_journal_step& step) override;
  /*! \brief Compare and atomically publish the bounded journal cursor.
   *  \param expected Current cursor identity expected by the owner, or empty
   *         only for initial publication.
   *  \param cursor Exact desired cursor.
   *  \return The desired cursor after durable publication, including exact
   *          idempotent retry of an already-visible desired value.
   *  \throws journal_store_error On stale expectation, I/O, or corruption.
   */
  [[nodiscard]] application_journal_cursor compare_and_publish_cursor(
      const std::optional<application_journal_cursor_identity>& expected,
      const application_journal_cursor& cursor) override;
  /*! \brief Load one exact immutable declaration by identity.
   *  \param identity Exact declaration address.
   *  \return Decoded declaration, or empty when that exact namespace/value is absent.
   *  \throws journal_store_error On malformed retained authority.
   */
  [[nodiscard]] std::optional<application_journal_declaration>
  load_declaration(
      const application_journal_declaration_identity& identity) override;
  /*! \brief Load the bounded cursor for one exact declaration.
   *  \param declaration Exact declaration address.
   *  \return Current cursor, or empty when none is retained.
   *  \throws journal_store_error On malformed retained authority.
   */
  [[nodiscard]] std::optional<application_journal_cursor> load_cursor(
      const application_journal_declaration_identity& declaration) override;
  /*! \brief Load one immutable journal step by exact declaration and sequence.
   *  \param declaration Exact declaration address.
   *  \param sequence Exact zero-based step sequence.
   *  \return Decoded step, or empty when the exact step is absent.
   *  \throws journal_store_error On malformed retained authority.
   */
  [[nodiscard]] std::optional<application_journal_step> load_step(
      const application_journal_declaration_identity& declaration,
      std::uint64_t sequence) override;

  /*! \brief Resolve the direct locator for the latest declaration of a request.
   *  \param request Exact semantic application-request identity.
   *  \return Exact declaration identity, or empty when no attempt is indexed.
   *  \throws journal_store_error If the locator or referenced declaration is
   *          malformed, missing, or names another request.
   *
   * This mutable locator is published only after the referenced immutable
   * declaration is durable. It is an exact restart address, not application
   * history, attempt-selection policy, or a directory-discovery mechanism.
   */
  [[nodiscard]] std::optional<application_journal_declaration_identity>
  load_active_declaration(const application_request_identity& request);

private:
  explicit application_journal_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

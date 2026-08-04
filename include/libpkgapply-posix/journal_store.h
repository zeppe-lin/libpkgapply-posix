// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/journal.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the FD-anchored journal store. */
enum class journal_store_error_code : std::uint8_t {
  directory_open_failed,
  directory_invalid,
  snapshot_open_failed,
  snapshot_read_failed,
  snapshot_write_failed,
  snapshot_sync_failed,
  snapshot_rename_failed,
  directory_sync_failed,
  snapshot_corrupt,
  snapshot_conflict,
};

/*! \brief I/O, corruption, or monotonicity failure in durable journal storage. */
class journal_store_error final : public std::runtime_error {
public:
  journal_store_error(
      journal_store_error_code code,
      int system_error,
      std::string message,
      bool replacement_visible = false);

  [[nodiscard]] journal_store_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] bool replacement_visible() const noexcept;

private:
  journal_store_error_code code_;
  int system_error_;
  bool replacement_visible_;
};

/*! \brief Atomic FD-anchored store for one snapshot per journal identity. */
class application_journal_store final {
public:
  /*! \brief Open a real directory without following a final symlink. */
  [[nodiscard]] static application_journal_store open(
      const std::string& directory);

  /*! \brief Duplicate and retain an already-open directory descriptor. */
  [[nodiscard]] static application_journal_store from_directory_fd(
      int directory_fd);

  application_journal_store(const application_journal_store&) = delete;
  application_journal_store& operator=(const application_journal_store&) = delete;
  application_journal_store(application_journal_store&& other) noexcept;
  application_journal_store& operator=(application_journal_store&& other) noexcept;
  ~application_journal_store();

  /*! \brief Atomically publish an exact or monotonic successor snapshot. */
  [[nodiscard]] application_journal_record publish(
      const application_journal_record& record);

  /*! \brief Load and validate the current snapshot for one journal identity. */
  [[nodiscard]] std::optional<application_journal_record> load(
      const application_journal_identity& journal) const;

private:
  explicit application_journal_store(int directory_fd) noexcept;

  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

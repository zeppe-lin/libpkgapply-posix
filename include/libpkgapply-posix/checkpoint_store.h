// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/restart_checkpoint_codec.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the FD-anchored checkpoint store. */
enum class checkpoint_store_error_code : std::uint8_t {
  directory_open_failed,
  directory_invalid,
  snapshot_open_failed,
  snapshot_read_failed,
  snapshot_write_failed,
  snapshot_sync_failed,
  snapshot_publish_failed,
  directory_sync_failed,
  snapshot_corrupt,
  snapshot_conflict,
};

/*! \brief I/O, corruption, or immutability failure in checkpoint storage. */
class checkpoint_store_error final : public std::runtime_error {
public:
  checkpoint_store_error(
      checkpoint_store_error_code code,
      int system_error,
      std::string message,
      bool publication_visible = false);

  [[nodiscard]] checkpoint_store_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] bool publication_visible() const noexcept;

private:
  checkpoint_store_error_code code_;
  int system_error_;
  bool publication_visible_;
};

/*! \brief Immutable FD-anchored checkpoint store keyed by journal snapshot. */
class application_restart_checkpoint_store final {
public:
  [[nodiscard]] static application_restart_checkpoint_store open(
      const std::string& directory);
  [[nodiscard]] static application_restart_checkpoint_store from_directory_fd(
      int directory_fd);

  application_restart_checkpoint_store(
      const application_restart_checkpoint_store&) = delete;
  application_restart_checkpoint_store& operator=(
      const application_restart_checkpoint_store&) = delete;
  application_restart_checkpoint_store(
      application_restart_checkpoint_store&& other) noexcept;
  application_restart_checkpoint_store& operator=(
      application_restart_checkpoint_store&& other) noexcept;
  ~application_restart_checkpoint_store();

  /*! \brief Publish one immutable checkpoint, accepting exact republication. */
  [[nodiscard]] application_restart_checkpoint publish(
      const application_journal_record& journal,
      const application_restart_checkpoint& checkpoint);

  [[nodiscard]] std::optional<application_restart_checkpoint> load(
      const application_journal_record& journal,
      const installation_application_request& request) const;
  [[nodiscard]] std::optional<application_restart_checkpoint> load(
      const application_journal_record& journal,
      const upgrade_application_request& request) const;
  [[nodiscard]] std::optional<application_restart_checkpoint> load(
      const application_journal_record& journal,
      const removal_application_request& request) const;

private:
  explicit application_restart_checkpoint_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

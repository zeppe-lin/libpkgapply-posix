// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include <libpkgapply/completed_evidence_codec.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the completed-evidence store. */
enum class completed_evidence_store_error_code : std::uint8_t {
  directory_open_failed,
  directory_invalid,
  record_open_failed,
  record_read_failed,
  record_write_failed,
  record_sync_failed,
  record_publish_failed,
  record_invalid,
  record_conflict,
  namespace_sync_failed,
};

/*! \brief I/O, corruption, or immutability failure in evidence storage. */
class completed_evidence_store_error final : public std::runtime_error {
public:
  completed_evidence_store_error(
      completed_evidence_store_error_code code,
      int system_error,
      std::string message,
      bool publication_visible = false);

  [[nodiscard]] completed_evidence_store_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] bool publication_visible() const noexcept;

private:
  completed_evidence_store_error_code code_;
  int system_error_;
  bool publication_visible_;
};

/*! \brief FD-anchored immutable store keyed by completed-evidence identity. */
class completed_application_evidence_store final {
public:
  [[nodiscard]] static completed_application_evidence_store open(
      const std::string& directory);
  [[nodiscard]] static completed_application_evidence_store from_directory_fd(
      int directory_fd);

  completed_application_evidence_store(
      const completed_application_evidence_store&) = delete;
  completed_application_evidence_store& operator=(
      const completed_application_evidence_store&) = delete;
  completed_application_evidence_store(
      completed_application_evidence_store&& other) noexcept;
  completed_application_evidence_store& operator=(
      completed_application_evidence_store&& other) noexcept;
  ~completed_application_evidence_store();

  /*! \brief Publish one installation record against its immutable request. */
  [[nodiscard]] completed_application_evidence_identity publish(
      const completed_application_evidence& evidence,
      const installation_application_request& request) const;
  /*! \brief Publish one upgrade record against its immutable request. */
  [[nodiscard]] completed_application_evidence_identity publish(
      const completed_application_evidence& evidence,
      const upgrade_application_request& request) const;
  /*! \brief Publish one removal record against its immutable request. */
  [[nodiscard]] completed_application_evidence_identity publish(
      const completed_application_evidence& evidence,
      const removal_application_request& request) const;

  [[nodiscard]] std::optional<completed_application_evidence> load(
      const completed_application_evidence_identity& identity,
      const installation_application_request& request) const;
  [[nodiscard]] std::optional<completed_application_evidence> load(
      const completed_application_evidence_identity& identity,
      const upgrade_application_request& request) const;
  [[nodiscard]] std::optional<completed_application_evidence> load(
      const completed_application_evidence_identity& identity,
      const removal_application_request& request) const;

  /*! \brief Synchronize visible evidence records and namespace metadata. */
  void synchronize() const;

private:
  explicit completed_application_evidence_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

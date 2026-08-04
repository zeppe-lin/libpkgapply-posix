// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

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
  directory_open_failed,
  directory_invalid,
  attempt_open_failed,
  attempt_invalid,
  attempt_locked,
  binding_read_failed,
  binding_write_failed,
  binding_mismatch,
  source_mismatch,
  source_unavailable,
  payload_open_failed,
  payload_read_failed,
  payload_write_failed,
  payload_sync_failed,
  payload_mismatch,
  record_read_failed,
  record_write_failed,
  record_invalid,
  record_publish_failed,
  namespace_sync_failed,
  object_not_regular,
};

/*! \brief POSIX rejected-object publication failure. */
class rejected_store_error final : public std::runtime_error {
public:
  rejected_store_error(rejected_store_error_code code,
                       int system_error,
                       std::string path,
                       std::string message);

  [[nodiscard]] rejected_store_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] const std::string& path() const noexcept;

private:
  rejected_store_error_code code_;
  int system_error_;
  std::string path_;
};

/*! \brief Exact authority from which one rejected record was published. */
enum class rejected_object_source : std::uint8_t {
  incoming = 1,
  old = 2,
};

/*! \brief Stable read-only descriptor for one rejected regular payload. */
class rejected_regular_object final {
public:
  rejected_regular_object(const rejected_regular_object&) = delete;
  rejected_regular_object& operator=(const rejected_regular_object&) = delete;
  rejected_regular_object(rejected_regular_object&& other) noexcept;
  rejected_regular_object& operator=(rejected_regular_object&& other) noexcept;
  ~rejected_regular_object();

  [[nodiscard]] int descriptor() const noexcept;
  [[nodiscard]] std::uint64_t size() const noexcept;

private:
  friend class published_rejected_object;
  rejected_regular_object(int descriptor, std::uint64_t size) noexcept;

  int descriptor_ = -1;
  std::uint64_t size_ = 0;
};

/*! \brief One immutable rejected record reopened from canonical storage. */
class published_rejected_object final {
public:
  published_rejected_object(const published_rejected_object&) = delete;
  published_rejected_object& operator=(const published_rejected_object&) = delete;
  published_rejected_object(published_rejected_object&& other) noexcept;
  published_rejected_object& operator=(published_rejected_object&& other) noexcept;
  ~published_rejected_object();

  [[nodiscard]] const application_attempt& attempt() const noexcept;
  [[nodiscard]] const pkgplan::operation_plan_identity& plan() const noexcept;
  [[nodiscard]] const backend_rejected_effect_request& request() const noexcept;
  [[nodiscard]] rejected_object_source source() const noexcept;
  [[nodiscard]] const application_path_observation& observation() const noexcept;
  [[nodiscard]] const rejected_object_record_identity& identity() const noexcept;

  /*! \brief Open verified self-contained bytes for a regular rejected object. */
  [[nodiscard]] rejected_regular_object open_regular() const;

private:
  class implementation;
  friend class application_rejected_object_store;
  explicit published_rejected_object(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief FD-anchored attempt-scoped immutable rejected-object namespace. */
class application_rejected_object_store final {
public:
  [[nodiscard]] static application_rejected_object_store open(
      const std::string& directory);
  [[nodiscard]] static application_rejected_object_store from_directory_fd(
      int directory_fd);

  application_rejected_object_store(
      const application_rejected_object_store&) = delete;
  application_rejected_object_store& operator=(
      const application_rejected_object_store&) = delete;
  application_rejected_object_store(
      application_rejected_object_store&& other) noexcept;
  application_rejected_object_store& operator=(
      application_rejected_object_store&& other) noexcept;
  ~application_rejected_object_store();

  /*! \brief Publish an incoming non-regular record from exact image authority. */
  [[nodiscard]] rejected_object_publication_result publish_incoming(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request,
      const pkgimage::package_image& image) const;

  /*! \brief Publish an incoming record with exact sealed payload authority. */
  [[nodiscard]] rejected_object_publication_result publish_incoming(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request,
      const pkgimage::package_image& image,
      const sealed_application_payloads& payloads) const;

  /*! \brief Publish one old record from exact pre-mutation capture authority. */
  [[nodiscard]] rejected_object_publication_result publish_old(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request,
      const captured_old_object& captured) const;

  /*! \brief Reopen one exact immutable record, or no value when unpublished. */
  [[nodiscard]] std::optional<published_rejected_object> load(
      const application_attempt& attempt,
      const pkgplan::operation_plan_identity& plan,
      const backend_rejected_effect_request& request) const;

  /*! \brief Synchronize one attempt's rejected records and namespace parents. */
  void synchronize(const application_attempt& attempt) const;

private:
  explicit application_rejected_object_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

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
  directory_open_failed,
  directory_invalid,
  target_root_open_failed,
  target_root_invalid,
  attempt_open_failed,
  attempt_invalid,
  attempt_locked,
  binding_read_failed,
  binding_write_failed,
  binding_mismatch,
  path_resolution_failed,
  source_open_failed,
  source_stat_failed,
  source_read_failed,
  source_changed,
  source_mismatch,
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

/*! \brief POSIX capture failure before active-target mutation authority. */
class capture_store_error final : public std::runtime_error {
public:
  capture_store_error(capture_store_error_code code,
                      int system_error,
                      std::string path,
                      std::string message);

  [[nodiscard]] capture_store_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] const std::string& path() const noexcept;

private:
  capture_store_error_code code_;
  int system_error_;
  std::string path_;
};

/*! \brief Stable read-only descriptor for one captured regular object. */
class captured_regular_object final {
public:
  captured_regular_object(const captured_regular_object&) = delete;
  captured_regular_object& operator=(const captured_regular_object&) = delete;
  captured_regular_object(captured_regular_object&& other) noexcept;
  captured_regular_object& operator=(captured_regular_object&& other) noexcept;
  ~captured_regular_object();

  [[nodiscard]] int descriptor() const noexcept;
  [[nodiscard]] std::uint64_t size() const noexcept;

private:
  friend class captured_old_object;
  captured_regular_object(int descriptor, std::uint64_t size) noexcept;

  int descriptor_ = -1;
  std::uint64_t size_ = 0;
};

/*! \brief One immutable old-object capture reopened from private storage. */
class captured_old_object final {
public:
  captured_old_object(const captured_old_object&) = delete;
  captured_old_object& operator=(const captured_old_object&) = delete;
  captured_old_object(captured_old_object&& other) noexcept;
  captured_old_object& operator=(captured_old_object&& other) noexcept;
  ~captured_old_object();

  [[nodiscard]] const application_attempt& attempt() const noexcept;
  [[nodiscard]] const old_object_capture_request& request() const noexcept;
  [[nodiscard]] const application_path_observation& observation() const noexcept;
  [[nodiscard]] bool exact_recovery_possible() const noexcept;

  /*! \brief Open verified captured bytes for a regular object. */
  [[nodiscard]] captured_regular_object open_regular() const;

private:
  class implementation;
  friend class application_capture_store;
  explicit captured_old_object(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief FD-anchored private store for admitted pre-mutation objects. */
class application_capture_store final {
public:
  /*! \brief Open private storage and target root without following final symlinks. */
  [[nodiscard]] static application_capture_store open(
      const std::string& directory,
      const std::string& target_root);

  /*! \brief Duplicate and retain already-open storage and target-root descriptors. */
  [[nodiscard]] static application_capture_store from_directory_fds(
      int directory_fd,
      int target_root_fd);

  application_capture_store(const application_capture_store&) = delete;
  application_capture_store& operator=(const application_capture_store&) = delete;
  application_capture_store(application_capture_store&& other) noexcept;
  application_capture_store& operator=(application_capture_store&& other) noexcept;
  ~application_capture_store();

  /*! \brief Capture one admitted present object into attempt-bound storage. */
  [[nodiscard]] old_object_capture_result capture(
      const application_attempt& attempt,
      const old_object_capture_request& request,
      const application_path_observation& admitted) const;

  /*! \brief Reopen one exact immutable capture, or no value when unpublished. */
  [[nodiscard]] std::optional<captured_old_object> load(
      const application_attempt& attempt,
      const old_object_capture_request& request,
      const application_path_observation& admitted) const;

  /*! \brief Synchronize one attempt's capture namespace and its parent. */
  void synchronize(const application_attempt& attempt) const;

private:
  application_capture_store(int directory_fd, int target_root_fd) noexcept;
  int directory_fd_ = -1;
  int target_root_fd_ = -1;
};

} // namespace pkgapply::posix

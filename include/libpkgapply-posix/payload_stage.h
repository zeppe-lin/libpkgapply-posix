// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

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
  directory_open_failed,
  directory_invalid,
  stage_open_failed,
  stage_invalid,
  stage_locked,
  binding_read_failed,
  binding_write_failed,
  binding_mismatch,
  entry_unexpected,
  entry_order_invalid,
  entry_open_failed,
  entry_read_failed,
  entry_write_failed,
  entry_sync_failed,
  entry_size_mismatch,
  entry_content_mismatch,
  stage_sync_failed,
  stage_publish_failed,
  stage_not_sealed,
};

/*! \brief POSIX staging failure before active-target mutation authority. */
class payload_stage_error final : public std::runtime_error {
public:
  payload_stage_error(payload_stage_error_code code,
                      int system_error,
                      std::string message);

  [[nodiscard]] payload_stage_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;

private:
  payload_stage_error_code code_;
  int system_error_;
};

/*! \brief Validated read-only descriptor for one sealed regular payload. */
class staged_regular_payload final {
public:
  staged_regular_payload(const staged_regular_payload&) = delete;
  staged_regular_payload& operator=(const staged_regular_payload&) = delete;
  staged_regular_payload(staged_regular_payload&& other) noexcept;
  staged_regular_payload& operator=(staged_regular_payload&& other) noexcept;
  ~staged_regular_payload();

  [[nodiscard]] int descriptor() const noexcept;
  [[nodiscard]] pkgimage::entry_id entry() const noexcept;
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
class sealed_application_payloads final {
public:
  sealed_application_payloads(const sealed_application_payloads&) = delete;
  sealed_application_payloads& operator=(const sealed_application_payloads&) = delete;
  sealed_application_payloads(sealed_application_payloads&& other) noexcept;
  sealed_application_payloads& operator=(sealed_application_payloads&& other) noexcept;
  ~sealed_application_payloads();

  [[nodiscard]] const application_attempt& attempt() const noexcept;
  [[nodiscard]] const application_attempt_nonce& attempt_nonce() const noexcept;
  [[nodiscard]] const pkgimage::package_image_identity& image() const noexcept;
  [[nodiscard]] const pkgimage::entry_selection& selection() const noexcept;
  [[nodiscard]] staged_regular_payload open(pkgimage::entry_id entry) const;

private:
  class implementation;
  friend class application_payload_store;
  explicit sealed_application_payloads(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief Backend payload sink backed by one private attempt directory. */
class application_payload_stage final : public incoming_payload_stage {
public:
  application_payload_stage(const application_payload_stage&) = delete;
  application_payload_stage& operator=(const application_payload_stage&) = delete;
  application_payload_stage(application_payload_stage&&) = delete;
  application_payload_stage& operator=(application_payload_stage&&) = delete;
  ~application_payload_stage() override;

  void begin(const pkgimage::package_entry& entry) override;
  void write(const pkgimage::package_entry& entry,
             const std::byte* data,
             std::size_t size) override;
  void end(const pkgimage::package_entry& entry) override;
  [[nodiscard]] backend_operation_result seal() override;
  void abandon() noexcept override;
  [[nodiscard]] bool sealed() const noexcept override;

private:
  class implementation;
  friend class application_payload_store;
  explicit application_payload_stage(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

/*! \brief FD-anchored namespace for private incoming regular payloads. */
class application_payload_store final {
public:
  [[nodiscard]] static application_payload_store open(
      const std::string& directory);
  [[nodiscard]] static application_payload_store from_directory_fd(
      int directory_fd);

  application_payload_store(const application_payload_store&) = delete;
  application_payload_store& operator=(const application_payload_store&) = delete;
  application_payload_store(application_payload_store&& other) noexcept;
  application_payload_store& operator=(application_payload_store&& other) noexcept;
  ~application_payload_store();

  [[nodiscard]] std::unique_ptr<application_payload_stage> begin(
      const application_attempt& attempt,
      const pkgimage::package_image& image,
      const pkgimage::entry_selection& selection) const;

  [[nodiscard]] std::optional<sealed_application_payloads> load(
      const application_attempt& attempt,
      const pkgimage::package_image& image,
      const pkgimage::entry_selection& selection) const;

  /*! \brief Synchronize namespace directory metadata after publication. */
  void synchronize() const;

private:
  explicit application_payload_store(int directory_fd) noexcept;
  int directory_fd_ = -1;
};

} // namespace pkgapply::posix

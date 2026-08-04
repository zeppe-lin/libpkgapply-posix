// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

#include <libpkgapply/attempt.h>
#include <libpkgplan/package_path.h>

namespace pkgapply::posix::detail {

enum class active_workspace_error_code : std::uint8_t {
  target_root_invalid,
  path_resolution_failed,
  workspace_inspection_failed,
  workspace_collision,
};

class active_workspace_error final : public std::runtime_error {
public:
  active_workspace_error(active_workspace_error_code code,
                         int system_error,
                         std::string path,
                         std::string message);

  [[nodiscard]] active_workspace_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] const std::string& path() const noexcept;

private:
  active_workspace_error_code code_;
  int system_error_;
  std::string path_;
};

enum class active_workspace_state : std::uint8_t {
  clear,
  prepared,
  displaced,
  removed_with_displaced_old,
  published_with_displaced_old,
  contradictory,
};

class active_workspace_snapshot final {
public:
  active_workspace_snapshot(active_workspace_state state,
                            bool final_present,
                            bool prepared_present,
                            bool displaced_present) noexcept;

  [[nodiscard]] active_workspace_state state() const noexcept;
  [[nodiscard]] bool final_present() const noexcept;
  [[nodiscard]] bool prepared_present() const noexcept;
  [[nodiscard]] bool displaced_present() const noexcept;

private:
  active_workspace_state state_;
  bool final_present_;
  bool prepared_present_;
  bool displaced_present_;
};

class active_path_workspace final {
public:
  active_path_workspace(const active_path_workspace&) = delete;
  active_path_workspace& operator=(const active_path_workspace&) = delete;
  active_path_workspace(active_path_workspace&& other) noexcept;
  active_path_workspace& operator=(active_path_workspace&& other) noexcept;
  ~active_path_workspace();

  [[nodiscard]] int parent_descriptor() const noexcept;
  [[nodiscard]] const pkgplan::package_path& path() const noexcept;
  [[nodiscard]] const std::string& leaf() const noexcept;
  [[nodiscard]] const std::string& prepared_name() const noexcept;
  [[nodiscard]] const std::string& displaced_name() const noexcept;
  [[nodiscard]] active_workspace_snapshot inspect() const;

private:
  friend class application_active_workspace;
  active_path_workspace(int parent_fd,
                        pkgplan::package_path path,
                        std::string leaf,
                        std::string prepared_name,
                        std::string displaced_name) noexcept;

  int parent_fd_ = -1;
  pkgplan::package_path path_;
  std::string leaf_;
  std::string prepared_name_;
  std::string displaced_name_;
};

class application_active_workspace final {
public:
  [[nodiscard]] static application_active_workspace from_directory_fd(
      int target_root_fd,
      application_attempt attempt);

  application_active_workspace(const application_active_workspace&) = delete;
  application_active_workspace& operator=(
      const application_active_workspace&) = delete;
  application_active_workspace(application_active_workspace&& other) noexcept;
  application_active_workspace& operator=(
      application_active_workspace&& other) noexcept;
  ~application_active_workspace();

  [[nodiscard]] const application_attempt& attempt() const noexcept;
  [[nodiscard]] int target_root_descriptor() const noexcept;
  [[nodiscard]] active_path_workspace open(
      const pkgplan::package_path& path) const;

private:
  application_active_workspace(int target_root_fd,
                               application_attempt attempt) noexcept;

  int target_root_fd_ = -1;
  application_attempt attempt_;
};

} // namespace pkgapply::posix::detail

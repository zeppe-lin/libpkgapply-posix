// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <libpkgapply/backend.h>

namespace pkgapply::posix {

/*! \brief Failure class reported by the FD-anchored target observer. */
enum class target_observer_error_code : std::uint8_t {
  root_open_failed,
  root_invalid,
  path_resolution_failed,
  object_open_failed,
  object_stat_failed,
  object_read_failed,
  content_hash_failed,
};

/*! \brief POSIX observation failure that cannot be represented as path truth. */
class target_observer_error final : public std::runtime_error {
public:
  target_observer_error(target_observer_error_code code,
                        int system_error,
                        std::string path,
                        std::string message);

  [[nodiscard]] target_observer_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;
  [[nodiscard]] const std::string& path() const noexcept;

private:
  target_observer_error_code code_;
  int system_error_;
  std::string path_;
};

/*! \brief Expected logical anchor used to prove one hard-link relation. */
class target_hardlink_expectation final {
public:
  target_hardlink_expectation(pkgplan::package_path path,
                              pkgplan::package_path anchor);

  [[nodiscard]] const pkgplan::package_path& path() const noexcept;
  [[nodiscard]] const pkgplan::package_path& anchor() const noexcept;

private:
  pkgplan::package_path path_;
  pkgplan::package_path anchor_;
};

/*! \brief Read-only observer anchored to one already-selected target root. */
class application_target_observer final {
public:
  /*! \brief Open a real directory without following a final symlink. */
  [[nodiscard]] static application_target_observer open(
      const std::string& root);

  /*! \brief Duplicate and retain an already-open directory descriptor. */
  [[nodiscard]] static application_target_observer from_directory_fd(
      int directory_fd);

  application_target_observer(const application_target_observer&) = delete;
  application_target_observer& operator=(const application_target_observer&) = delete;
  application_target_observer(application_target_observer&& other) noexcept;
  application_target_observer& operator=(application_target_observer&& other) noexcept;
  ~application_target_observer();

  /*! \brief Observe one exact path closure without following path symlinks. */
  [[nodiscard]] backend_observation_batch observe(
      std::vector<pkgplan::package_path> paths,
      std::vector<target_hardlink_expectation> hardlinks = {}) const;

private:
  explicit application_target_observer(int root_fd) noexcept;
  int root_fd_ = -1;
};

} // namespace pkgapply::posix

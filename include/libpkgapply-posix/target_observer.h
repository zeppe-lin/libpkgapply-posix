// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file target_observer.h
 *  \brief Descriptor-anchored observation of one managed target root.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <libpkgapply/backend.h>

namespace pkgapply::posix {

/*! \brief Stable failure class for target observation. */
enum class target_observer_error_code : std::uint8_t {
  root_open_failed, /*!< Configured target root could not be opened safely. */
  root_invalid, /*!< Retained root authority is not a usable directory. */
  path_resolution_failed, /*!< Logical path could not be resolved beneath root. */
  object_open_failed, /*!< Target object could not be opened for observation. */
  object_stat_failed, /*!< Object metadata could not be observed stably. */
  object_read_failed, /*!< Regular content could not be read completely. */
  content_hash_failed, /*!< Regular-content identity could not be computed. */
};

/*! \brief POSIX observation failure not representable as target-path truth. */
class PKGAPPLY_POSIX_API target_observer_error final
    : public std::runtime_error {
public:
  /*! \brief Construct one typed observation failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param path Exact logical or diagnostic path.
   *  \param message Human-readable diagnostic text.
   */
  target_observer_error(target_observer_error_code code,
                        int system_error,
                        std::string path,
                        std::string message);

  /*! \brief Destroy the polymorphic observation failure. */
  ~target_observer_error() override;

  /*! \brief Return the stable mechanism failure class. */
  [[nodiscard]] target_observer_error_code code() const noexcept;
  /*! \brief Return captured errno, or zero when inapplicable. */
  [[nodiscard]] int system_error() const noexcept;
  /*! \brief Return the exact diagnostic path. */
  [[nodiscard]] const std::string& path() const noexcept;

private:
  target_observer_error_code code_;
  int system_error_;
  std::string path_;
};

/*! \brief Expected logical anchor used to prove one hard-link relation. */
class PKGAPPLY_POSIX_API target_hardlink_expectation final {
public:
  /*! \brief Construct one path-to-anchor expectation.
   *  \param path Logical hard-link path.
   *  \param anchor Logical path expected to share the same object.
   */
  target_hardlink_expectation(pkgplan::package_path path,
                              pkgplan::package_path anchor);

  /*! \brief Return the logical hard-link path. */
  [[nodiscard]] const pkgplan::package_path& path() const noexcept;
  /*! \brief Return the expected logical anchor path. */
  [[nodiscard]] const pkgplan::package_path& anchor() const noexcept;

private:
  pkgplan::package_path path_;
  pkgplan::package_path anchor_;
};

/*! \brief Read-only observer anchored to one already-selected target root. */
class PKGAPPLY_POSIX_API application_target_observer final {
public:
  /*! \brief Open and retain a real directory without following a final symlink.
   *  \param root Caller-selected target-root pathname.
   *  \return Move-only descriptor-anchored observer.
   *  \throws target_observer_error If opening or validating root fails.
   */
  [[nodiscard]] static application_target_observer open(
      const std::string& root);

  /*! \brief Duplicate and retain an already-open directory descriptor.
   *  \param directory_fd Caller-selected target-root descriptor.
   *  \return Move-only descriptor-anchored observer.
   *  \throws target_observer_error If duplication or validation fails.
   */
  [[nodiscard]] static application_target_observer from_directory_fd(
      int directory_fd);

  application_target_observer(const application_target_observer&) = delete;
  application_target_observer& operator=(
      const application_target_observer&) = delete;
  application_target_observer(application_target_observer&& other) noexcept;
  application_target_observer& operator=(
      application_target_observer&& other) noexcept;
  /*! \brief Close the retained target-root descriptor. */
  ~application_target_observer();

  /*! \brief Observe one exact path closure without following path symlinks.
   *  \param paths Complete logical path set requested by semantic authority.
   *  \param hardlinks Expected hard-link relations within that set.
   *  \return Complete observation batch for every requested path.
   *  \throws target_observer_error If safe observation cannot be completed.
   *  \throws std::invalid_argument If path or hard-link authority is invalid.
   */
  [[nodiscard]] backend_observation_batch observe(
      std::vector<pkgplan::package_path> paths,
      std::vector<target_hardlink_expectation> hardlinks = {}) const;

private:
  explicit application_target_observer(int root_fd) noexcept;
  int root_fd_ = -1;
};

} // namespace pkgapply::posix

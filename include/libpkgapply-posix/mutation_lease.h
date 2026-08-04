// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <libpkgapply/mutation_lease.h>

namespace pkgapply::posix {

/*! \brief Failure acquiring or retaining one POSIX target mutation lease. */
enum class target_mutation_lease_error_code : std::uint8_t {
  directory_invalid = 1,
  directory_duplicate_failed = 2,
  lock_open_failed = 3,
  lock_not_regular = 4,
  lock_busy = 5,
  lock_failed = 6,
  lock_replaced = 7,
  nonce_failed = 8,
};

/*! \brief POSIX exclusion-mechanism failure before target mutation. */
class target_mutation_lease_error final : public std::runtime_error {
public:
  target_mutation_lease_error(target_mutation_lease_error_code code,
                              int system_error,
                              std::string message);

  [[nodiscard]] target_mutation_lease_error_code code() const noexcept;
  [[nodiscard]] int system_error() const noexcept;

private:
  target_mutation_lease_error_code code_;
  int system_error_;
};

/*! \brief Caller-owned nonblocking POSIX target mutation exclusion authority.
 *
 * acquire() duplicates one already-selected lock-directory descriptor, opens
 * the lock file derived from the target's exclusion-domain identity without
 * following a final symlink, and attempts LOCK_EX | LOCK_NB.  The lock file is
 * never removed.  The caller retains the returned object through application,
 * installed-state publication, and finalization or recovery.
 */
class target_mutation_lease final : public pkgapply::target_mutation_lease {
public:
  /*! \brief Attempt one acquisition in an explicit lock directory.
   *
   * Waiting and retry policy remain outside this library.  A competing live
   * holder is reported as lock_busy.
   */
  [[nodiscard]] static std::unique_ptr<target_mutation_lease> acquire(
      const application_target_context& target,
      int lock_directory_fd);

  target_mutation_lease(const target_mutation_lease&) = delete;
  target_mutation_lease& operator=(const target_mutation_lease&) = delete;
  target_mutation_lease(target_mutation_lease&&) = delete;
  target_mutation_lease& operator=(target_mutation_lease&&) = delete;
  ~target_mutation_lease() override;

  [[nodiscard]] const mutation_lease_instance_identity&
  identity() const noexcept override;
  [[nodiscard]] const application_target_context_identity&
  target() const noexcept override;
  [[nodiscard]] const mutation_exclusion_domain_identity&
  exclusion_domain() const noexcept override;
  [[nodiscard]] bool held() const noexcept override;

private:
  class implementation;
  explicit target_mutation_lease(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

} // namespace pkgapply::posix

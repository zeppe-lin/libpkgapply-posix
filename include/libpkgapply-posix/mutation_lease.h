// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file mutation_lease.h
 *  \brief Nonblocking POSIX target-mutation exclusion.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include <libpkgapply/mutation_lease.h>

/*! \namespace pkgapply::posix
 *  \brief Descriptor-anchored POSIX mechanisms for libpkgapply.
 */
namespace pkgapply::posix {

/*! \brief Stable failure class for POSIX mutation-lease acquisition. */
enum class target_mutation_lease_error_code : std::uint8_t {
  directory_invalid = 1, /*!< Lock-directory descriptor is not a usable directory. */
  directory_duplicate_failed = 2, /*!< Retaining the directory descriptor failed. */
  lock_open_failed = 3, /*!< Coordination file could not be opened safely. */
  lock_not_regular = 4, /*!< Coordination authority is not a regular file. */
  lock_busy = 5, /*!< Another live holder owns the nonblocking lock. */
  lock_failed = 6, /*!< Advisory lock acquisition or inspection failed. */
  lock_replaced = 7, /*!< Named coordination file was unlinked or replaced. */
  nonce_failed = 8, /*!< Mechanism-issued acquisition nonce could not be created. */
};

/*! \brief POSIX exclusion-mechanism failure before target mutation. */
class PKGAPPLY_POSIX_API target_mutation_lease_error final
    : public std::runtime_error {
public:
  /*! \brief Construct one typed lease failure.
   *  \param code Stable mechanism failure class.
   *  \param system_error Captured errno value, or zero when inapplicable.
   *  \param message Human-readable diagnostic text.
   */
  target_mutation_lease_error(target_mutation_lease_error_code code,
                              int system_error,
                              std::string message);

  /*! \brief Destroy the polymorphic lease failure. */
  ~target_mutation_lease_error() override;

  /*!
   * \brief Return the stable mechanism failure class.
  *  \return The stable mechanism failure class.
   */
  [[nodiscard]] target_mutation_lease_error_code code() const noexcept;
  /*!
   * \brief Return captured errno, or zero when inapplicable.
  *  \return Captured errno, or zero when inapplicable.
   */
  [[nodiscard]] int system_error() const noexcept;

private:
  target_mutation_lease_error_code code_;
  int system_error_;
};

/*! \brief Caller-owned nonblocking POSIX target-mutation authority.
 *
 *  Acquisition duplicates one already-selected lock-directory descriptor,
 *  opens the domain-derived coordination file without following a final
 *  symlink, and attempts `LOCK_EX | LOCK_NB`. The file is never removed. The
 *  caller retains this object through application, state publication, and
 *  finalization or recovery.
 */
class PKGAPPLY_POSIX_API target_mutation_lease final
    : public pkgapply::target_mutation_lease {
public:
  /*! \brief Attempt one acquisition in an explicit lock directory.
   *  \param target Exact semantic target and exclusion-domain authority.
   *  \param lock_directory_fd Already-open selected directory descriptor.
   *  \return Unique caller-owned held lease.
   *  \throws target_mutation_lease_error On invalid authority, contention,
   *          descriptor failure, lock failure, or nonce failure.
   *
   *  Waiting, retry, and backoff policy remain outside this provider.
   */
  [[nodiscard]] static std::unique_ptr<target_mutation_lease> acquire(
      const application_target_context& target,
      int lock_directory_fd);

  /*! \brief Provider objects forbid copy construction. */
  target_mutation_lease(const target_mutation_lease&) = delete;
  /*! \brief Provider objects forbid copy assignment. */
  target_mutation_lease& operator=(const target_mutation_lease&) = delete;
  /*! \brief Provider objects forbid move construction. */
  target_mutation_lease(target_mutation_lease&&) = delete;
  /*! \brief Provider objects forbid move assignment. */
  target_mutation_lease& operator=(target_mutation_lease&&) = delete;
  /*! \brief Release the advisory lock and retained descriptors. */
  ~target_mutation_lease() override;

  /*!
   * \brief Return exact mechanism-issued lease identity.
  *  \return Exact mechanism-issued lease identity.
   */
  [[nodiscard]] const mutation_lease_instance_identity&
  identity() const noexcept override;
  /*!
   * \brief Return exact bound target-context identity.
  *  \return Exact bound target-context identity.
   */
  [[nodiscard]] const application_target_context_identity&
  target() const noexcept override;
  /*!
   * \brief Return exact mutation-exclusion-domain identity.
  *  \return Exact mutation-exclusion-domain identity.
   */
  [[nodiscard]] const mutation_exclusion_domain_identity&
  exclusion_domain() const noexcept override;
  /*!
   * \brief Revalidate that named lock authority remains held.
  *  \return Whether the named lock authority remains held.
   */
  [[nodiscard]] bool held() const noexcept override;

private:
  class implementation;
  explicit target_mutation_lease(std::unique_ptr<implementation> state);
  std::unique_ptr<implementation> state_;
};

} // namespace pkgapply::posix

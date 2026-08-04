// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file version.h
 *  \brief Public provider API and release versions.
 */
#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <string_view>

namespace pkgapply::posix {

/*! \brief Public provider API generation inherited from the in-tree product. */
inline constexpr std::uint32_t api_version = 2;

/*! \brief Return the linked libpkgapply-posix release version.
 *  \return Static semantic-version string with process lifetime.
 */
[[nodiscard]] PKGAPPLY_POSIX_API std::string_view version() noexcept;

} // namespace pkgapply::posix

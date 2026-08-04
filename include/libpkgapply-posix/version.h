// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <libpkgapply-posix/export.h>

#include <cstdint>
#include <string_view>

namespace pkgapply::posix {

/** Public ABI generation inherited from the in-tree POSIX product. */
inline constexpr std::uint32_t api_version = 2;

/** Return the independent product version. */
[[nodiscard]] PKGAPPLY_POSIX_API std::string_view version() noexcept;

} // namespace pkgapply::posix

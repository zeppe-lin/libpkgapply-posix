// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file export.h
 *  \brief Public symbol-visibility contract for libpkgapply-posix.
 */

#pragma once

#if defined(_WIN32) || defined(__CYGWIN__)
#  if defined(PKGAPPLY_POSIX_BUILDING_LIBRARY)
#    define PKGAPPLY_POSIX_API __declspec(dllexport)
#  else
#    define PKGAPPLY_POSIX_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define PKGAPPLY_POSIX_API __attribute__((visibility("default")))
#else
#  define PKGAPPLY_POSIX_API
#endif

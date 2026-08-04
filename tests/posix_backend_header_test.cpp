// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/backend.h>

#include <type_traits>

int main()
{
  static_assert(std::is_base_of_v<
      pkgapply::application_backend,
      pkgapply::posix::application_posix_backend>);
  return 0;
}

// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/libpkgapply-posix.h>
#include <libpkgapply/version.h>

#include <type_traits>

static_assert(std::is_base_of_v<
    pkgapply::application_backend,
    pkgapply::posix::application_posix_backend>);
static_assert(std::is_base_of_v<
    pkgapply::target_mutation_lease,
    pkgapply::posix::target_mutation_lease>);

int main()
{
  return pkgapply::version() == "2.3.0" ? 0 : 1;
}

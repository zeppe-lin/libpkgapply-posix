// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgapply-posix/rejected_store.h>

int main()
{
  return static_cast<int>(
      pkgapply::posix::rejected_object_source::incoming) == 1 ? 0 : 1;
}

#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
build=$1
pc=$build/meson-private/libpkgapply-posix.pc
[ -s "$pc" ] || { echo "pkgconfig-metadata: missing $pc" >&2; exit 1; }
grep -F 'Version: 4.0.0' "$pc" >/dev/null
grep -F -- '-lpkgapply-posix' "$pc" >/dev/null
public=$(sed -n 's/^Requires:[[:space:]]*//p' "$pc")
private=$(sed -n 's/^Requires\.private:[[:space:]]*//p' "$pc")
private_libs=$(sed -n 's/^Libs\.private:[[:space:]]*//p' "$pc")
has_requirement() {
  printf '%s\n' "$1" | tr ',' '\n' | awk \
    -v package="$2" -v version="$3" '
      $1 == package && $2 == ">=" && $3 == version { found = 1 }
      END { exit found ? 0 : 1 }
    '
}
has_requirement "$public" libpkgapply 4.0.0 || {
  echo 'pkgconfig-metadata: missing public libpkgapply >= 4.0.0' >&2
  exit 1
}
printf '%s\n' "$public" | tr ',' '\n' | awk '$1 == "libpkgapply" && $2 == "<" && $3 == "5.0.0" { found = 1 } END { exit found ? 0 : 1 }' || {
  echo 'pkgconfig-metadata: missing public libpkgapply < 5.0.0' >&2
  exit 1
}
has_requirement "$public" libpkgimage 0.4.0 || {
  echo 'pkgconfig-metadata: missing public libpkgimage >= 0.4.0' >&2
  exit 1
}
if printf '%s\n' "$public" | grep -E 'libpkgplan|libcrypto|libpkgstate' >/dev/null; then
  echo 'pkgconfig-metadata: private or foreign edge leaked publicly' >&2
  exit 1
fi
has_requirement "$private" libpkgplan 0.3.0 || {
  echo 'pkgconfig-metadata: missing private libpkgplan >= 0.3.0' >&2
  exit 1
}
printf '%s\n%s\n' "$private" "$private_libs" | grep -F libcrypto >/dev/null || {
  echo 'pkgconfig-metadata: missing private libcrypto' >&2
  exit 1
}

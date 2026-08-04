#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 1 ] || {
  echo "usage: $0 INSTALLED-LIBRARY" >&2
  exit 2
}
library=$1
[ -s "$library" ] || {
  echo "shared-boundary-audit: missing library: $library" >&2
  exit 1
}

output=$(readelf -d "$library")
printf '%s\n' "$output"
printf '%s\n' "$output" | grep -F \
  'Library soname: [libpkgapply-posix.so.2]' >/dev/null || {
  echo 'shared-boundary-audit: wrong SONAME' >&2
  exit 1
}
needed=$(printf '%s\n' "$output" | grep 'Shared library:' || true)
for dependency in \
  'libpkgapply.so.2' \
  'libpkgimage.so.1' \
  'libpkgplan.so.1'
do
  printf '%s\n' "$needed" | grep -F \
    "Shared library: [$dependency]" >/dev/null || {
    echo "shared-boundary-audit: dependency is absent: $dependency" >&2
    exit 1
  }
done
if printf '%s\n' "$needed" | grep -E \
  'libpkgstate|libpkgexec|libyaml' >/dev/null
then
  echo 'shared-boundary-audit: orchestration or foreign syntax dependency is present' >&2
  exit 1
fi

nm -D --defined-only "$library" | c++filt >"$library.exports"
if grep -E ' [TWV] ' "$library.exports" | grep -vE \
  'pkgapply::posix::|typeinfo (for|name for) pkgapply::posix::|vtable for pkgapply::posix::|LIBPKGAPPLY_POSIX_2| _init$| _fini$' \
  >/dev/null
then
  echo 'shared-boundary-audit: foreign C++ export is present' >&2
  exit 1
fi
rm -f "$library.exports"

#!/bin/sh
set -eu
root=$1
fail(){ echo "release-contract: $*" >&2; exit 1; }
grep -F "version: '3.2.2'" "$root/meson.build" >/dev/null || fail 'project version mismatch'
grep -F 'PROJECT_NUMBER         = 3.2.2' "$root/Doxyfile" >/dev/null || fail 'Doxygen version mismatch'
grep -F 'return "3.2.2";' "$root/src/version.cpp" >/dev/null || fail 'runtime version mismatch'
grep -F 'api_version = 2' "$root/include/libpkgapply-posix/version.h" >/dev/null || fail 'API generation mismatch'
block=$(sed -n '/^libpkgapply_dep = dependency(/,/^)/p' "$root/meson.build")
printf '%s\n' "$block" | grep -F "version: ['>=3.0.1', '<4.0.0']," >/dev/null ||
  fail 'source-ABI-4 application dependency interval mismatch'
grep -F 'Preserved the published POSIX ABI generation' "$root/HISTORY.md" >/dev/null || fail 'release lineage absent'

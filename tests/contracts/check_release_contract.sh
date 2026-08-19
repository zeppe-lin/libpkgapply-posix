#!/bin/sh
set -eu
root=$1
fail(){ echo "release-contract: $*" >&2; exit 1; }
grep -F "version: '4.0.0'" "$root/meson.build" >/dev/null || fail 'project version mismatch'
grep -F 'PROJECT_NUMBER         = 4.0.0' "$root/Doxyfile" >/dev/null || fail 'Doxygen version mismatch'
grep -F 'return "4.0.0";' "$root/src/version.cpp" >/dev/null || fail 'runtime version mismatch'
grep -F 'api_version = 3' "$root/include/libpkgapply-posix/version.h" >/dev/null || fail 'API generation mismatch'
grep -F "soversion: '3'" "$root/src/meson.build" >/dev/null || fail 'SONAME generation mismatch'
grep -F '## 4.0.0' "$root/HISTORY.md" >/dev/null || fail '4.0.0 history absent'
block=$(sed -n '/^libpkgapply_dep = dependency(/,/^)/p' "$root/meson.build")
printf '%s
' "$block" | grep -F "version: ['>=4.0.0', '<5.0.0']," >/dev/null ||
  fail 'application generation-4 dependency interval mismatch'
grep -F 'Removed the provider-owned restart-checkpoint store' "$root/HISTORY.md" >/dev/null ||
  fail 'generation-4 authority lineage absent'

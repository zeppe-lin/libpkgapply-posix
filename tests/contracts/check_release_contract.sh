#!/bin/sh
set -eu
root=$1
fail(){ echo "release-contract: $*" >&2; exit 1; }
grep -F "version: '3.1.0'" "$root/meson.build" >/dev/null || fail 'project version mismatch'
grep -F 'PROJECT_NUMBER         = 3.1.0' "$root/Doxyfile" >/dev/null || fail 'Doxygen version mismatch'
grep -F 'return "3.1.0";' "$root/src/version.cpp" >/dev/null || fail 'runtime version mismatch'
grep -F 'api_version = 2' "$root/include/libpkgapply-posix/version.h" >/dev/null || fail 'API generation mismatch'
grep -F 'Preserved the published POSIX ABI generation' "$root/HISTORY.md" >/dev/null || fail 'release lineage absent'

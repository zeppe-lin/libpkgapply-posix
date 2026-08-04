#!/bin/sh
set -eu
root=$1
fail(){ echo "abi-contract: $*" >&2; exit 1; }
grep -F "soversion: '2'" "$root/src/meson.build" >/dev/null || fail 'SONAME generation changed'
grep -F "gnu_symbol_visibility: 'hidden'" "$root/src/meson.build" >/dev/null || fail 'hidden visibility absent'
grep -F 'PKGAPPLY_POSIX_BUILDING_LIBRARY' "$root/src/meson.build" >/dev/null || fail 'library export mode absent'
grep -F '_ZN8pkgapply5posix*;' "$root/abi/libpkgapply-posix.exports" >/dev/null || fail 'namespace export map absent'
for h in "$root"/include/libpkgapply-posix/*.h; do
  case $(basename "$h") in export.h|version.h|libpkgapply-posix.h) continue;; esac
  if grep -E '^class ' "$h" | grep -v 'PKGAPPLY_POSIX_API' >/dev/null; then fail "unannotated public class in ${h#"$root"/}"; fi
done

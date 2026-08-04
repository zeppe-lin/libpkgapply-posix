#!/bin/sh
set -eu
root=$1
fail(){ echo "architecture-contract: $*" >&2; exit 1; }
! grep -R -E 'libpkgstate|pkgstate::|libpkgexec|pkgexec::' "$root/include" "$root/src" >/dev/null || fail 'foreign orchestration/state authority present'
grep -F "subdir('src')" "$root/meson.build" >/dev/null || fail 'library body not explicit'
grep -F "version: '>=3.0.0'" "$root/meson.build" >/dev/null || fail 'core 3.0 floor absent'
grep -F "version: '>=0.4.0'" "$root/meson.build" >/dev/null || fail 'image 0.4 floor absent'
grep -F "version: '>=0.3.0'" "$root/meson.build" >/dev/null || fail 'plan 0.3 floor absent'
! grep -F 'fallback:' "$root/meson.build" >/dev/null || fail 'repository fallback coupling present'

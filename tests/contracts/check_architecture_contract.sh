#!/bin/sh
set -eu

root=$1
fail() {
  echo "architecture-contract: $*" >&2
  exit 1
}

if grep -R -E 'libpkgstate|pkgstate::|libpkgexec|pkgexec::' \
  "$root/include" "$root/src" >/dev/null
then
  fail 'foreign orchestration or state authority present'
fi

grep -F "subdir('src')" "$root/meson.build" >/dev/null || \
  fail 'library body not explicit'
grep -F "version: '>=3.0.0'" "$root/meson.build" >/dev/null || \
  fail 'core 3.0 floor absent'
grep -F "version: '>=0.4.0'" "$root/meson.build" >/dev/null || \
  fail 'image 0.4 floor absent'
grep -F "version: '>=0.3.0'" "$root/meson.build" >/dev/null || \
  fail 'plan 0.3 floor absent'

if grep -F 'fallback:' "$root/meson.build" >/dev/null; then
  fail 'repository fallback coupling present'
fi

grep -F 'requires: [libpkgapply_dep, libpkgimage_dep]' \
  "$root/src/meson.build" >/dev/null || \
  fail 'public header closure is not explicit'
grep -F 'requires_private: [libpkgplan_dep, libcrypto_dep]' \
  "$root/src/meson.build" >/dev/null || \
  fail 'private mechanism closure is not explicit'

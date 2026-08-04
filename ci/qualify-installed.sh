#!/bin/sh
set -eu
[ "$#" -eq 2 ] || { echo 'usage: qualify-installed.sh BUILD-DIR {shared|static}' >&2; exit 2; }
build=$1; mode=$2
prefix=$build/install
deps=$(cat "$build/ci-dependency-prefix")
rm -rf "$prefix"
meson install -C "$build/product"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$deps/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
unset PKG_CONFIG_SYSROOT_DIR
[ "$(pkg-config --modversion libpkgapply-posix)" = 3.0.0 ] || exit 1
req=$(pkg-config --print-requires libpkgapply-posix)
printf '%s\n' "$req" | grep -F 'libpkgapply >= 3.0.0' >/dev/null
printf '%s\n' "$req" | grep -F 'libpkgimage >= 0.4.0' >/dev/null
printf '%s\n' "$req" | grep -F 'libpkgplan >= 0.3.0' >/dev/null
pkg-config --print-requires-private libpkgapply-posix | grep -F libcrypto >/dev/null
flags=''
[ "$mode" = static ] && flags=--static
cxx=${CXX:-c++}
# shellcheck disable=SC2046
$cxx -std=c++17 -Wall -Wextra -Wpedantic -Werror $(pkg-config $flags --cflags libpkgapply-posix) ci/installed-consumer.cpp $(pkg-config $flags --libs libpkgapply-posix) -o "$build/installed-consumer"
LD_LIBRARY_PATH="$prefix/lib:$deps/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$build/installed-consumer"
for h in "$prefix"/include/libpkgapply-posix/*.h; do unit="$build/$(basename "$h").cpp"; printf '#include <libpkgapply-posix/%s>\n' "$(basename "$h")" >"$unit"; $cxx -std=c++17 -Wall -Wextra -Wpedantic -Werror -fsyntax-only $(pkg-config --cflags libpkgapply-posix) "$unit"; done
if [ "$mode" = shared ]; then
  lib=$(find "$prefix/lib" -maxdepth 1 -type f -name 'libpkgapply-posix.so.*' | head -n1)
  readelf -d "$lib" | grep -F 'Library soname: [libpkgapply-posix.so.2]' >/dev/null
  readelf -d "$lib" | grep -F 'Shared library: [libpkgapply.so.2]' >/dev/null
  readelf -d "$lib" | grep -F 'Shared library: [libpkgimage.so.1]' >/dev/null
  readelf -d "$lib" | grep -F 'Shared library: [libpkgplan.so.1]' >/dev/null
  nm -D --defined-only "$lib" | c++filt >"$build/exports.txt"
  if grep -E ' [TWV] ' "$build/exports.txt" | grep -vE 'pkgapply::posix::|typeinfo (for|name for) pkgapply::posix::|vtable for pkgapply::posix::|LIBPKGAPPLY_POSIX_2| _init$| _fini$' >/dev/null; then echo 'foreign C++ export present' >&2; exit 1; fi
else
  [ -f "$prefix/lib/libpkgapply-posix.a" ]
fi

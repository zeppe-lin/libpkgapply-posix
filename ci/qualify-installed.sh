#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

usage() {
  echo 'usage: qualify-installed.sh BUILD-DIR {shared|static}' >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
build=$1
mode=$2
case $mode in
  shared|static) ;;
  *) usage ;;
esac

prefix=$build/install
deps=$(cat "$build/ci-dependency-prefix")
rm -rf "$prefix"
meson install -C "$build/product"

export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$deps/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$prefix/lib:$deps/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
unset PKG_CONFIG_SYSROOT_DIR

[ "$(pkg-config --modversion libpkgapply-posix)" = 3.1.0 ] || {
  echo 'installed libpkgapply-posix version is not 3.1.0' >&2
  exit 1
}

public=$(pkg-config --print-requires libpkgapply-posix)
printf '%s\n' "$public" | grep -F \
  'libpkgapply >= 3.0.0' >/dev/null || {
  echo 'missing public libpkgapply requirement' >&2
  exit 1
}
printf '%s\n' "$public" | grep -F \
  'libpkgimage >= 0.4.0' >/dev/null || {
  echo 'missing public libpkgimage requirement' >&2
  exit 1
}
if printf '%s\n' "$public" | grep -E \
  'libpkgplan|libcrypto|libpkgstate' >/dev/null
then
  echo 'private or foreign dependency leaked into Requires' >&2
  exit 1
fi

private=$(pkg-config --print-requires-private libpkgapply-posix)
printf '%s\n' "$private" | grep -F \
  'libpkgplan >= 0.3.0' >/dev/null || {
  echo 'missing private libpkgplan requirement' >&2
  exit 1
}
printf '%s\n' "$private" | grep -F libcrypto >/dev/null || {
  echo 'missing private libcrypto requirement' >&2
  exit 1
}

flags=
[ "$mode" = static ] && flags=--static
consumer_flags=$(pkg-config $flags --cflags --libs libpkgapply-posix)
case $mode in
  shared)
    if printf '%s\n' "$consumer_flags" | grep -E -- '-lpkgplan|-lcrypto' >/dev/null; then
      echo 'private planner or crypto edge leaked into shared consumer flags' >&2
      exit 1
    fi
    ;;
  static)
    for required in -lpkgplan -lcrypto; do
      printf '%s\n' "$consumer_flags" | grep -F -- "$required" >/dev/null || {
        echo "static link closure omits $required" >&2
        exit 1
      }
    done
    ;;
esac
cxx=${CXX:-c++}

# shellcheck disable=SC2046
$cxx -std=c++17 -Wall -Wextra -Wpedantic -Werror \
  $(pkg-config $flags --cflags libpkgapply-posix) \
  ci/installed-consumer.cpp \
  $(pkg-config $flags --libs libpkgapply-posix) \
  -o "$build/installed-consumer"
"$build/installed-consumer"

for header in "$prefix"/include/libpkgapply-posix/*.h; do
  unit=$build/$(basename "$header").cpp
  printf '#include <libpkgapply-posix/%s>\n' \
    "$(basename "$header")" >"$unit"
  # shellcheck disable=SC2046
  $cxx -std=c++17 -Wall -Wextra -Wpedantic -Werror -fsyntax-only \
    $(pkg-config --cflags libpkgapply-posix) "$unit"
done

if [ "$mode" = shared ]; then
  library=$(find "$prefix/lib" -maxdepth 1 -type f \
    -name 'libpkgapply-posix.so.*' -print -quit)
  [ -n "$library" ] || {
    echo 'installed shared library not found' >&2
    exit 1
  }
  "$(dirname "$0")/audit-shared-boundary.sh" "$library"
else
  [ -f "$prefix/lib/libpkgapply-posix.a" ] || {
    echo 'installed static archive not found' >&2
    exit 1
  }
fi

python3 ci/qualify-installed-documentation.py "$prefix" libpkgapply-posix

page=$build/product/man/libpkgapply-posix.3
if [ -e "$page" ]; then
  installed=$prefix/share/man/man3/libpkgapply-posix.3
  [ -s "$installed" ] || {
    echo "installed manual is absent: $installed" >&2
    exit 1
  }
fi

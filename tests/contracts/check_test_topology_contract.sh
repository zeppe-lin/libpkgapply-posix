#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 1 ] || {
  echo "usage: $0 SOURCE-ROOT" >&2
  exit 2
}
root=$1
meson_file=$root/tests/meson.build
manifest=$root/abi/libpkgapply-posix.exports

fail()
{
  echo "test-topology-contract: $*" >&2
  exit 1
}

[ -s "$meson_file" ] || fail 'tests/meson.build is absent'

grep -F "static_library(" "$meson_file" >/dev/null ||
  fail 'private implementation test library is absent'
grep -F "'pkgapply-posix-test-implementation'" "$meson_file" >/dev/null ||
  fail 'private implementation test library has no stable target name'
grep -F 'libpkgapply_posix_sources,' "$meson_file" >/dev/null ||
  fail 'private tests do not compile the production implementation sources'
grep -F 'install: false,' "$meson_file" >/dev/null ||
  fail 'private implementation test library is installable'

if grep -F "include_directories('../src')" "$meson_file" >/dev/null; then
  fail 'test reaches private headers without the private test dependency'
fi

block()
{
  name=$1
  sed -n "/  $name = executable(/,/^  )/p" "$meson_file"
}

for name in posix_active_incoming_test posix_active_recovery_test; do
  output=$(block "$name")
  printf '%s\n' "$output" | grep -F \
    'dependencies: internal_crypto_test_deps,' >/dev/null ||
    fail "$name does not use the private implementation plus direct crypto"
done

for name in posix_active_removal_test posix_active_workspace_test; do
  output=$(block "$name")
  printf '%s\n' "$output" | grep -F \
    'dependencies: libpkgapply_posix_internal_test_dep,' >/dev/null ||
    fail "$name does not use the private implementation test dependency"
done

expected='posix_active_incoming_test.cpp
posix_active_recovery_test.cpp
posix_active_removal_test.cpp
posix_active_workspace_test.cpp'
actual=$(
  grep -l -E '^#include "(active_namespace|active_workspace)\.h"' \
    "$root"/tests/*.cpp |
  sed 's|.*/||' |
  LC_ALL=C sort
)
[ "$actual" = "$expected" ] || {
  printf '%s\n' 'expected private-header tests:' "$expected" >&2
  printf '%s\n' 'actual private-header tests:' "$actual" >&2
  fail 'private-header test set changed without an explicit topology review'
}

for source in "$root"/tests/*.cpp; do
  case $(basename "$source") in
    posix_active_incoming_test.cpp|posix_active_recovery_test.cpp|\
    posix_active_removal_test.cpp|posix_active_workspace_test.cpp)
      ;;
    *)
      if grep -F 'pkgapply::posix::detail' "$source" >/dev/null; then
        fail "public-consumer test names private implementation: ${source#"$root"/}"
      fi
      ;;
  esac
done

if grep -F 'pkgapply5posix6detail' "$manifest" >/dev/null; then
  fail 'private detail namespace leaked into the installed ABI manifest'
fi

if sed -n '/install_headers(/,/^)/p' "$root/src/meson.build" |
   grep -E "active_(namespace|workspace)\.h" >/dev/null
then
  fail 'private active-namespace header is installed'
fi

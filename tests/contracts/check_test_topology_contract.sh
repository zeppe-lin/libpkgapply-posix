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
fail(){ echo "test-topology-contract: $*" >&2; exit 1; }

for directory in unit mechanism integration header fixtures contracts; do
  [ -d "$root/tests/$directory" ] || fail "missing tests/$directory"
done
[ -s "$meson_file" ] || fail 'tests/meson.build is absent'
[ -f "$root/tests/integration/durability_failure_test.cpp" ] ||
  fail 'durability failure regression is missing'
[ -f "$root/tests/header/public_header_compile.cpp" ] ||
  fail 'generic public-header harness is missing'

if find "$root/tests" -maxdepth 1 -type f \( -name '*.cpp' -o -name '*.h' -o -name '*.sh' \) | grep . >/dev/null; then
  fail 'tests, fixtures, or shell contracts remain in the tests root'
fi
if find "$root/tests" -type f -name '*_header_test.cpp' | grep . >/dev/null; then
  fail 'legacy one-file header harness remains'
fi
if grep -n "test('header:" "$meson_file" >/dev/null 2>&1; then
  fail 'deprecated colon appears in header test names'
fi
for suite in unit mechanism integration header contract; do
  grep -F "suite: '$suite'" "$meson_file" >/dev/null ||
    fail "Meson does not register the $suite suite"
done

grep -F "static_library(" "$meson_file" >/dev/null ||
  fail 'private implementation test library is absent'
grep -F "'pkgapply-posix-test-implementation'" "$meson_file" >/dev/null ||
  fail 'private implementation test library has no stable target name'
grep -F 'libpkgapply_posix_sources,' "$meson_file" >/dev/null ||
  fail 'private tests do not compile the production implementation sources'
grep -F 'install: false,' "$meson_file" >/dev/null ||
  fail 'private implementation test library is installable'

expected='posix_active_incoming_test.cpp
posix_active_recovery_test.cpp
posix_active_removal_test.cpp
posix_active_workspace_test.cpp'
actual=$(
  grep -l -E '^#include "(active_namespace|active_workspace)\.h"' \
    "$root"/tests/mechanism/*.cpp |
  sed 's|.*/||' |
  LC_ALL=C sort
)
[ "$actual" = "$expected" ] || {
  printf '%s\n' 'expected private-header tests:' "$expected" >&2
  printf '%s\n' 'actual private-header tests:' "$actual" >&2
  fail 'private-header test set changed without an explicit topology review'
}

for source in "$root"/tests/unit/*.cpp "$root"/tests/integration/*.cpp \
              "$root"/tests/header/*.cpp; do
  if grep -F 'pkgapply::posix::detail' "$source" >/dev/null; then
    fail "public-consumer test names private implementation: ${source#"$root"/}"
  fi
done

if grep -F 'pkgapply5posix6detail' "$manifest" >/dev/null; then
  fail 'private detail namespace leaked into the installed ABI manifest'
fi
if sed -n '/install_headers(/,/^)/p' "$root/src/meson.build" |
   grep -E 'active_(namespace|workspace)\.h' >/dev/null
then
  fail 'private active-namespace header is installed'
fi

# The reference provider must prove the semantic durability-failure channel;
# merely calling fsync(2) in store implementations is not qualification.
grep -F 'fail_next_fsync' "$root/tests/integration/durability_failure_test.cpp" >/dev/null ||
  fail 'durability regression does not inject a real synchronization failure'
grep -F 'application_durability_status::unconfirmed' \
  "$root/tests/integration/durability_failure_test.cpp" >/dev/null ||
  fail 'durability regression does not require unconfirmed semantic evidence'
grep -F 'fail_next_fsync' \
  "$root/tests/mechanism/posix_active_removal_test.cpp" >/dev/null ||
  fail 'active-namespace mechanism lacks synchronization fault injection'
grep -F 'application_durability_status::unconfirmed' \
  "$root/tests/mechanism/posix_active_removal_test.cpp" >/dev/null ||
  fail 'active-namespace fault is not classified as unconfirmed'

echo 'test-topology-contract: ok'

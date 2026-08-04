#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 1 ] || {
  echo "usage: $0 SOURCE-ROOT" >&2
  exit 2
}
root=$1

fail()
{
  echo "ci-contract: $*" >&2
  exit 1
}

for file in \
  .github/workflows/ci.yml \
  ci/configure-and-test.sh \
  ci/qualify-installed.sh \
  ci/audit-shared-boundary.sh \
  ci/lint-manpages.sh \
  ci/installed-consumer.cpp
do
  [ -s "$root/$file" ] || fail "missing $file"
done
for script in "$root"/ci/*.sh "$root"/tests/contracts/*.sh "$root"/tests/*.sh; do
  sh -n "$script" || fail "invalid shell: ${script#"$root"/}"
done
for token in \
  v3.0.0 v2.0.0 v1.0.0 v0.4.0 v0.3.0 \
  'GCC shared' 'GCC static' 'Clang shared' 'Clang static' \
  'GCC release' 'address,undefined' 'meson==1.10.2'
do
  grep -F "$token" "$root/.github/workflows/ci.yml" >/dev/null ||
    fail "CI omits $token"
done

grep -F 'libpkgapply.so.2' "$root/ci/audit-shared-boundary.sh" >/dev/null ||
  fail 'shared audit omits the semantic core SONAME'
grep -F 'libpkgplan.so.1' "$root/ci/audit-shared-boundary.sh" >/dev/null ||
  fail 'shared audit omits the direct planner mechanism edge'

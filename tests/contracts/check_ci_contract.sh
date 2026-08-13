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
  ci/installed-consumer.cpp \
  tests/contracts/check_test_topology_contract.sh
do
  [ -s "$root/$file" ] || fail "missing $file"
done
for script in "$root"/ci/*.sh "$root"/tests/contracts/*.sh; do
  sh -n "$script" || fail "invalid shell: ${script#"$root"/}"
done
for token in \
  v3.0.0 v3.0.1 v3.1.0 v1.0.0 v1.1.0 v0.4.1 v0.3.1 \
  'GCC shared' 'GCC static' 'Clang shared' 'Clang static' \
  'GCC release' 'address,undefined' 'meson==1.10.2'
do
  grep -F "$token" "$root/.github/workflows/ci.yml" >/dev/null ||
    fail "CI omits $token"
done

for dependency in \
  'libpkgimage v0.4.1' \
  'libpkgplan v0.3.1' \
  'libpkgsource v3.0.1' \
  'libpkgstate v3.1.0' \
  'libpkgcatalog v3.0.1' \
  'libpkgresolve v3.0.0' \
  'libpkgsource-plan v1.1.0' \
  'libpkgapply v3.0.0'
do
  repository=${dependency% *}
  reference=${dependency#* }
  count=$(awk -v repository="repository: zeppe-lin/$repository" \
              -v reference="ref: $reference" '
    index($0, repository) {
      waiting = 1
      next
    }
    waiting && index($0, reference) {
      count += 1
      waiting = 0
      next
    }
    waiting && /repository:/ {
      waiting = 0
    }
    END { print count + 0 }
  ' "$root/.github/workflows/ci.yml")
  [ "$count" -eq 2 ] ||
    fail "CI does not qualify $repository at $reference in both matrices"
done


grep -F 'libpkgapply.so.3' "$root/ci/audit-shared-boundary.sh" >/dev/null ||
  fail 'shared audit omits the semantic core SONAME'
grep -F 'libpkgplan.so.1' "$root/ci/audit-shared-boundary.sh" >/dev/null ||
  fail 'shared audit omits the direct planner mechanism edge'

grep -F 'application_target_observer::open' \
  "$root/ci/installed-consumer.cpp" >/dev/null ||
  fail 'installed consumer does not execute target observation'
grep -F 'application_rejected_object_store::open' \
  "$root/ci/installed-consumer.cpp" >/dev/null ||
  fail 'installed consumer does not pull the private store closure'
if grep -E '&pkgapply::posix::[A-Za-z_][A-Za-z0-9_]*' \
  "$root/ci/installed-consumer.cpp" >/dev/null
then
  fail 'installed consumer regressed to address-only linkage'
fi

grep -F 'html_docs: enabled' "$root/.github/workflows/ci.yml" >/dev/null || fail 'GCC shared HTML build is absent'
grep -F 'pandoc' "$root/.github/workflows/ci.yml" >/dev/null || fail 'Pandoc qualification dependency is absent'
grep -F -- '-Dhtml_docs=' "$root/.github/workflows/ci.yml" >/dev/null || fail 'HTML Meson feature is not configured'
grep -F 'qualify-html-docs.sh' "$root/.github/workflows/ci.yml" >/dev/null || fail 'installed HTML qualification is absent'

if grep -F 'ref: v2.0.0' "$root/.github/workflows/ci.yml" >/dev/null; then
  fail 'CI retains retired resolver v2.0.0 authority'
fi

if grep -F 'scdoc' "$root/.github/workflows/ci.yml" >/dev/null; then
  fail 'CI retains retired scdoc dependency'
fi

if grep -F 'ref: v0.4.0' "$root/.github/workflows/ci.yml" >/dev/null; then
  fail 'CI retains retired libpkgimage v0.4.0 authority'
fi

#!/bin/sh
set -eu
root=$1
fail(){ echo "ci-contract: $*" >&2; exit 1; }
for f in "$root/.github/workflows/ci.yml" "$root/ci/configure-and-test.sh" "$root/ci/qualify-installed.sh" "$root/ci/installed-consumer.cpp"; do [ -s "$f" ] || fail "missing ${f#"$root"/}"; done
for s in "$root"/ci/*.sh "$root"/tests/contracts/*.sh "$root"/tests/*.sh; do sh -n "$s" || fail "invalid shell: ${s#"$root"/}"; done
grep -F 'v3.0.0' "$root/.github/workflows/ci.yml" >/dev/null || fail 'core release dependency not pinned'
grep -F 'v0.4.0' "$root/.github/workflows/ci.yml" >/dev/null || fail 'image release dependency not pinned'
grep -F 'v0.3.0' "$root/.github/workflows/ci.yml" >/dev/null || fail 'plan release dependency not pinned'

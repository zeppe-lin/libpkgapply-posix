#!/bin/sh
set -eu
root=$1
fail(){ echo "documentation-contract: $*" >&2; exit 1; }
for f in README.md CONTRIBUTING.md MAINTAINING.md HISTORY.md docs/architecture.md docs/integration.md docs/testing.md docs/abi.md docs/code-style.md docs/history/libpkgapply-2.3-extraction.md man/libpkgapply-posix.3.scdoc; do [ -s "$root/$f" ] || fail "missing $f"; done
grep -F 'does not construct package plans' "$root/README.md" >/dev/null || fail 'non-ownership not explicit'
grep -F 'descriptor-anchored' "$root/docs/architecture.md" >/dev/null || fail 'authority retention not documented'
python3 "$root/tools/check-public-documentation.py" \
  "$root" libpkgapply-posix libpkgapply-posix.h

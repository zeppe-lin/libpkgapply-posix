#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -ge 1 ] || {
  echo "usage: $0 SOURCE-ROOT [DEPENDENCY-INCLUDE-ROOT ...]" >&2
  exit 2
}
root=$1
shift
fail(){ echo "documentation-contract: $*" >&2; exit 1; }

resolve_include()
{
  package=$1
  value=${2:-}
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return
  fi
  command -v pkg-config >/dev/null 2>&1 ||
    fail "$package include root is unavailable"
  pkg-config --exists "$package" ||
    fail "$package include root is unavailable"
  pkg-config --variable=includedir "$package"
}

packages='libpkgapply
libpkgbuild-plan
libpkgplan
libpkgbuild-image
libpkgbuild
libpkgimage
libpkgsource-plan
libpkgsource
libpkgresolve
libpkgcatalog
libpkgstate'
include_roots=
for package in $packages; do
  value=${1:-}
  [ "$#" -eq 0 ] || shift
  include=$(resolve_include "$package" "$value")
  include_roots="$include_roots --include-root $include"
done

for f in README.md CONTRIBUTING.md MAINTAINING.md HISTORY.md \
  DESIGN.md TESTING.md docs/integration.md docs/abi.md \
  docs/code-style.md docs/history/libpkgapply-2.3-extraction.md \
  docs/man/libpkgapply-posix.3.md
do
  [ -s "$root/$f" ] || fail "missing $f"
done
grep -F 'does not construct package plans' "$root/README.md" >/dev/null ||
  fail 'non-ownership not explicit'
grep -F 'descriptor-anchored' "$root/DESIGN.md" >/dev/null ||
  fail 'authority retention not documented'
python3 "$root/tools/check-public-documentation.py" \
  "$root" libpkgapply-posix libpkgapply-posix.h
if command -v clang++ >/dev/null 2>&1; then
  # shellcheck disable=SC2086
  python3 "$root/tools/check-doxygen-contract.py" \
    --root "$root" --include-subdir libpkgapply-posix \
    $include_roots \
    --namespace pkgapply --clang "$(command -v clang++)"
fi

"$root/tests/contracts/check_manpage_source.sh" "$root"
"$root/tests/contracts/check_manpage_normalizer.sh" "$root"
python3 "$root/tools/check-html-manifest.py" \
  --root "$root" --project libpkgapply-posix

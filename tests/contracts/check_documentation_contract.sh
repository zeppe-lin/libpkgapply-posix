#!/bin/sh
set -eu
root=$1
fail(){ echo "documentation-contract: $*" >&2; exit 1; }
apply_include=${2:-}
image_include=${3:-}
plan_include=${4:-}

resolve_include()
{
  package=$1
  value=$2
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

apply_include=$(resolve_include libpkgapply "$apply_include")
image_include=$(resolve_include libpkgimage "$image_include")
plan_include=$(resolve_include libpkgplan "$plan_include")
for f in README.md CONTRIBUTING.md MAINTAINING.md HISTORY.md docs/architecture.md docs/integration.md docs/testing.md docs/abi.md docs/code-style.md docs/history/libpkgapply-2.3-extraction.md man/libpkgapply-posix.3.scdoc; do [ -s "$root/$f" ] || fail "missing $f"; done
grep -F 'does not construct package plans' "$root/README.md" >/dev/null || fail 'non-ownership not explicit'
grep -F 'descriptor-anchored' "$root/docs/architecture.md" >/dev/null || fail 'authority retention not documented'
python3 "$root/tools/check-public-documentation.py" \
  "$root" libpkgapply-posix libpkgapply-posix.h
if command -v clang++ >/dev/null 2>&1; then
  python3 "$root/tools/check-doxygen-contract.py" \
    --root "$root" --include-subdir libpkgapply-posix \
    --include-root "$apply_include" \
    --include-root "$image_include" \
    --include-root "$plan_include" \
    --namespace pkgapply --clang "$(command -v clang++)"
fi

python3 "$root/tools/check-man-markdown.py" \
  --root "$root" --project libpkgapply-posix --version 3.1.0
python3 "$root/tools/check-html-manifest.py" \
  --root "$root" --project libpkgapply-posix

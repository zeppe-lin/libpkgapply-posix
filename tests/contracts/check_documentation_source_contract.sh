#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
fail(){ echo "documentation-source-contract: $*" >&2; exit 1; }

for file in README.md DESIGN.md TESTING.md HISTORY.md MAINTAINING.md CONTRIBUTING.md \
            docs/abi.md docs/code-style.md docs/html.md docs/integration.md \
            docs/manpage-markdown.md docs/mechanisms.md docs/qualification.md \
            docs/history/libpkgapply-2.3-extraction.md; do
  path=$root/$file
  [ -s "$path" ] || fail "missing $file"
  first=$(sed -n '/[^[:space:]]/ { p; q; }' "$path")
  case "$first" in
    '# '*) ;;
    *) fail "$file does not begin with an ATX level-one heading" ;;
  esac
  count=$(grep -c '^# ' "$path" || true)
  [ "$count" -eq 1 ] || fail "$file must contain exactly one ATX level-one heading"
done

if grep -R -n -E --include='*.md' --exclude-dir=.git \
     '^(=+|-+|~+)$' "$root"/*.md "$root"/docs/*.md "$root"/docs/history/*.md \
     >/dev/null 2>&1; then
  fail 'maintained project prose contains Setext-style underline headings'
fi
[ ! -e "$root/docs/architecture.md" ] || fail 'duplicate docs/architecture.md authority remains'
[ ! -e "$root/docs/testing.md" ] || fail 'duplicate docs/testing.md authority remains'
[ ! -e "$root/man" ] || fail 'legacy root man/ authority remains'
if find "$root" -type f \( -name '*.scd' -o -name '*.scdoc' \) | grep . >/dev/null; then
  fail 'scdoc manual authority remains'
fi
[ -s "$root/docs/man/libpkgapply-posix.3.md" ] || fail 'canonical Markdown manual is absent'
[ -s "$root/docs/man/generated/libpkgapply-posix.3" ] || fail 'generated roff derivative is absent'
grep -F '% LIBPKGAPPLY-POSIX(3) libpkgapply-posix | Version 3.2.1' \
  "$root/docs/man/libpkgapply-posix.3.md" >/dev/null || fail 'manual title/version metadata is absent'

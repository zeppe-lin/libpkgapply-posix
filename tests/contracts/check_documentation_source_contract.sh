#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
fail(){ echo "documentation-source-contract: $*" >&2; exit 1; }

for file in README.md HISTORY.md MAINTAINING.md CONTRIBUTING.md docs/*.md; do
  path="$root/$file"
  [ -s "$path" ] || continue
  first=$(sed -n '/[^[:space:]]/ { p; q; }' "$path")
  case "$first" in
    '# '*) ;;
    *) fail "$file does not begin with an ATX level-one heading" ;;
  esac
done

if grep -R -n -E --include='*.md' --exclude-dir=.git \
     '^(=+|-+|~+)$' "$root" >/dev/null 2>&1; then
  fail 'maintained Markdown contains Setext-style underline headings'
fi

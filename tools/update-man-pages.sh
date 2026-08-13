#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

usage()
{
  echo "usage: $0 --check|--write [pandoc] [source-root]" >&2
  exit 2
}

fail()
{
  echo "update-man-pages: $*" >&2
  exit 1
}

[ "$#" -ge 1 ] && [ "$#" -le 3 ] || usage
mode=$1
pandoc=${2:-pandoc}
root=${3:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}

case $mode in
  --check | --write) ;;
  *) usage ;;
esac

command -v "$pandoc" >/dev/null 2>&1 || fail "Pandoc not found: $pandoc"
version=$($pandoc --version | sed -n '1s/^pandoc //p')
major=${version%%.*}
remainder=${version#*.}
minor=${remainder%%.*}
case $major:$minor in
  *[!0-9:]* | :* | *:) fail "cannot parse Pandoc version: $version" ;;
esac
if [ "$major" -ne 3 ] || [ "$minor" -lt 1 ]; then
  fail "Pandoc 3.1 through 3.x is required; found $version"
fi

canonicalizer=$root/tools/canonicalize-man-roff.awk
highlighting_option=--no-highlight
if "$pandoc" --help 2>/dev/null | grep -F -- '--syntax-highlighting' >/dev/null; then
  highlighting_option=--syntax-highlighting=none
fi

[ -f "$canonicalizer" ] || fail 'missing roff canonicalizer'
mkdir -p "$root/docs/man/generated"

page=libpkgapply-posix.3
source=$root/docs/man/$page.md
output=$root/docs/man/generated/$page
[ -f "$source" ] || fail "missing source: ${source#$root/}"
raw=$(mktemp)
temporary=$(mktemp)
trap 'rm -f "$raw" "$temporary"' EXIT HUP INT TERM

"$pandoc" \
  --from=markdown-smart \
  --to=man \
  --standalone \
  --fail-if-warnings \
  --eol=lf \
  --wrap=none \
  "$highlighting_option" \
  "$source" > "$raw"

printf '.\\" Generated from docs/man/%s.md; do not edit.\n' "$page" > "$temporary"
sed '1d' "$raw" | awk -f "$canonicalizer" >> "$temporary"

case $mode in
  --write)
    cat "$temporary" > "$output"
    ;;
  --check)
    if [ ! -f "$output" ] || ! cmp -s "$temporary" "$output"; then
      [ ! -f "$output" ] || diff -u "$output" "$temporary" || true
      echo "update-man-pages: generated page is stale: $page" >&2
      exit 1
    fi
    ;;
esac

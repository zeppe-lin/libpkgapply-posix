#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

nm_tool=$1
library=$2
manifest=$3

fail()
{
  echo "abi-surface-test: $*" >&2
  exit 1
}

[ -s "$manifest" ] || fail 'ELF ABI manifest is missing or empty'

raw=$($nm_tool -D --defined-only --format=posix "$library") ||
  fail 'cannot inspect shared-library dynamic symbols'

expected=$(mktemp)
actual=$(mktemp)
trap 'rm -f "$expected" "$actual"' EXIT HUP INT TERM

sed -n '/^_Z[A-Za-z0-9_]*$/p' "$manifest" | LC_ALL=C sort -u > "$expected"
printf '%s\n' "$raw" |
  awk '$2 != "A" { symbol = $1; sub(/@.*/, "", symbol); print symbol }' |
  LC_ALL=C sort -u > "$actual"

if ! cmp -s "$expected" "$actual"; then
  diff -u "$expected" "$actual" || true
  fail 'dynamic symbol set differs from the reviewed ELF ABI manifest'
fi

if printf '%s\n' "$raw" | grep -E 'LIBPKGAPPLY_POSIX_' >/dev/null; then
  fail 'premature named ABI version node remains'
fi

#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
fail(){ echo "extraction-contract: $*" >&2; exit 1; }
command -v git >/dev/null 2>&1 || exit 77
git -C "$root" rev-parse --git-dir >/dev/null 2>&1 || exit 77
origin=$(git -C "$root" rev-list --max-parents=0 HEAD)
[ "$(printf '%s\n' "$origin" | wc -l)" -eq 1 ] || fail 'repository has multiple roots'
manifest=$root/docs/history/libpkgapply-2.3-extraction.sha256
[ -s "$manifest" ] || fail 'missing extraction manifest'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/libpkgapply-posix-extraction.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
while read -r expected path; do
  git -C "$root" show "$origin:$path" >"$tmp/source" || fail "root omits $path"
  actual=$(sha256sum "$tmp/source" | awk '{print $1}')
  [ "$actual" = "$expected" ] || fail "root extraction differs: $path"
done <"$manifest"

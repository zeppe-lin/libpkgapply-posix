#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
fail(){ echo "manpage-source-test: $*" >&2; exit 1; }

source=$root/docs/man/libpkgapply-posix.3.md
[ -s "$source" ] || fail 'missing canonical source: docs/man/libpkgapply-posix.3.md'
first=$(sed -n '1p' "$source")
[ "$first" = '% LIBPKGAPPLY-POSIX(3) libpkgapply-posix | Version 4.0.0' ] ||
  fail "invalid Pandoc title: $first"
grep -F '# NAME' "$source" >/dev/null || fail 'NAME section missing'
grep -F '# SEE ALSO' "$source" >/dev/null || fail 'SEE ALSO section missing'

if find "$root/docs/man" -maxdepth 1 -type f \( -name '*.scd' -o -name '*.scdoc' \) | grep . >/dev/null; then
  fail 'scdoc source remains'
fi
if grep -RInE '^[-=]{3,}$' "$root/docs/man" --include='*.md' >/dev/null; then
  fail 'Setext heading remains in manual source'
fi

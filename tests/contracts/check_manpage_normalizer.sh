#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
normalizer=$root/tools/canonicalize-man-roff.awk
input=$(mktemp)
expected=$(mktemp)
actual=$(mktemp)
second=$(mktemp)
trap 'rm -f "$input" "$expected" "$actual" "$second"' EXIT HUP INT TERM
cat > "$input" <<'ROFF'
.EX
\f[B]<libpkgapply-posix/libpkgapply-posix.h>\f[R]
.EE
.IP \(bu 2
\(dq\(atvalue\(dq
ROFF
cat > "$expected" <<'ROFF'
.EX
<libpkgapply-posix/libpkgapply-posix.h>
.EE
.IP \[bu] 2
\[dq]\[at]value\[dq]
ROFF
awk -f "$normalizer" "$input" > "$actual"
cmp -s "$expected" "$actual" || { diff -u "$expected" "$actual"; exit 1; }
awk -f "$normalizer" "$actual" > "$second"
cmp -s "$actual" "$second" || { echo 'normalizer is not idempotent' >&2; exit 1; }

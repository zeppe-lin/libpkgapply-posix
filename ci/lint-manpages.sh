#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 1 ] || {
  echo "usage: $0 BUILD-DIR" >&2
  exit 2
}
page=$1/product/docs/man/libpkgapply-posix.3
[ -s "$page" ] || {
  echo "generated manual is absent: $page" >&2
  exit 1
}
output=$(mandoc -Tlint "$page" 2>&1) || {
  printf '%s\n' "$output" >&2
  exit 1
}
[ -z "$output" ] || {
  printf '%s\n' "$output" >&2
  exit 1
}

#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 2 ] || {
  echo "usage: $0 SOURCE-ROOT BUILD-ROOT" >&2
  exit 2
}
root=$1
# The build-root argument remains part of the common contract interface.  The
# style surface is derived from Git, so generated and untracked files are absent
# regardless of their location.
_build_root=$2

fail()
{
  echo "style-contract: $*" >&2
  exit 1
}

for file in .clang-format .editorconfig docs/code-style.md; do
  [ -s "$root/$file" ] || fail "missing $file"
done

tracked_text_files()
{
  git -C "$root" ls-files -z -- \
    '*.cpp' \
    '*.h' \
    '*.md' \
    '*.build' \
    '*.options' \
    '*.sh' \
    '*.yml'
}

tab_matches=$(
  cd "$root"
  tracked_text_files | xargs -0 -r grep -Hn "$(printf '\t')" || true
)
if [ -n "$tab_matches" ]; then
  printf '%s\n' "$tab_matches" >&2
  fail 'tab character present in tracked source'
fi

space_matches=$(
  cd "$root"
  tracked_text_files | xargs -0 -r grep -Hn -E '[[:blank:]]+$' || true
)
if [ -n "$space_matches" ]; then
  printf '%s\n' "$space_matches" >&2
  fail 'trailing whitespace present in tracked source'
fi

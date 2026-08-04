#!/bin/sh
set -eu

root=$1
fail() {
  echo "style-contract: $*" >&2
  exit 1
}

for file in .clang-format .editorconfig docs/code-style.md; do
  [ -s "$root/$file" ] || fail "missing $file"
done

text_files() {
  find "$root" \
    -path "$root/.git" -prune -o \
    -type f \( \
      -name '*.cpp' -o \
      -name '*.h' -o \
      -name '*.md' -o \
      -name '*.build' -o \
      -name '*.options' -o \
      -name '*.sh' -o \
      -name '*.yml' \
    \) -exec grep -Il '' {} +
}

if text_files | xargs -r grep -n "$(printf '\t')" >/dev/null; then
  fail 'tab character present'
fi

if text_files | xargs -r grep -n -E '[[:blank:]]+$' >/dev/null; then
  fail 'trailing whitespace present'
fi

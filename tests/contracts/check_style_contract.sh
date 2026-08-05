#!/bin/sh
set -eu

root=$1
build_root=$2
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
    -path "$build_root" -prune -o \
    -type d -path "$root/build*" -prune -o \
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

tab_matches=$(text_files | xargs -r grep -Hn "$(printf '\t')" || true)
if [ -n "$tab_matches" ]; then
  printf '%s\n' "$tab_matches" >&2
  fail 'tab character present'
fi

space_matches=$(text_files | xargs -r grep -Hn -E '[[:blank:]]+$' || true)
if [ -n "$space_matches" ]; then
  printf '%s\n' "$space_matches" >&2
  fail 'trailing whitespace present'
fi

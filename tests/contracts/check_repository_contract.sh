#!/bin/sh
set -eu
root=$1
fail(){ echo "repository-contract: $*" >&2; exit 1; }
for p in include/libpkgapply-posix src abi docs tests man ci .github/workflows; do [ -e "$root/$p" ] || fail "missing $p"; done
if git -C "$root" ls-files | grep -E \
  '(^|/)([^/]+\.(o|a|pyc)|[^/]+\.so(\..*)?)$' >/dev/null
then
  fail 'generated build product tracked'
fi
! grep -R -E 'subprojects/|fallback:' "$root/meson.build" "$root/src/meson.build" >/dev/null || fail 'embedded dependency coupling present'

test -x "$root/tools/check-public-documentation.py" || fail 'public documentation checker is absent'
test -x "$root/tools/check-doxygen-contract.py" || fail 'Doxygen contract checker is absent'

for tool in \
  build-html-docs.py check-html-docs.py install-html-docs.py \
  render-man-markdown.py check-man-markdown.py check-html-manifest.py; do
  test -x "$root/tools/$tool" || fail "missing executable tools/$tool"
done

for helper in \
  ci/qualify-html-docs.sh ci/qualify-installed-documentation.py; do
  test -x "$root/$helper" || fail "missing executable $helper"
done

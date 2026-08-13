#!/bin/sh
set -eu
root=$1
fail(){ echo "repository-contract: $*" >&2; exit 1; }
for p in include/libpkgapply-posix src abi docs docs/man docs/man/generated tests ci .github/workflows; do
  [ -e "$root/$p" ] || fail "missing $p"
done
[ -f "$root/meson.options" ] || fail 'meson.options is absent'
[ ! -e "$root/meson_options.txt" ] || fail 'legacy meson_options.txt is present'
[ -s "$root/DESIGN.md" ] || fail 'root DESIGN.md is absent'
[ -s "$root/TESTING.md" ] || fail 'root TESTING.md is absent'
[ -s "$root/HISTORY.md" ] || fail 'root HISTORY.md is absent'
[ ! -e "$root/docs/architecture.md" ] || fail 'duplicate docs/architecture.md authority remains'
[ ! -e "$root/docs/testing.md" ] || fail 'duplicate docs/testing.md authority remains'
[ ! -e "$root/man" ] || fail 'legacy root man/ authority remains'
if find "$root" -type f \( -name '*.scd' -o -name '*.scdoc' \) | grep . >/dev/null; then
  fail 'scdoc manual authority remains'
fi
! grep -F 'meson_options.txt' "$root/tools/check-html-manifest.py" >/dev/null || fail 'HTML tooling retains legacy Meson-options fallback'
if git -C "$root" ls-files | grep -E \
  '(^|/)([^/]+\.(o|a|pyc)|[^/]+\.so(\..*)?)$' >/dev/null
then
  fail 'generated build product tracked'
fi
! grep -R -E 'subprojects/|fallback:' "$root/meson.build" "$root/src/meson.build" >/dev/null || fail 'embedded dependency coupling present'

test -x "$root/tools/check-public-documentation.py" || fail 'public documentation checker is absent'
test -x "$root/tools/check-doxygen-contract.py" || fail 'Doxygen contract checker is absent'

grep -F -- '--include-root' "$root/tests/contracts/check_documentation_contract.sh" >/dev/null ||
  fail 'documentation parser dependency binding is absent'
grep -F "pkgconfig: 'includedir'" "$root/tests/meson.build" >/dev/null ||
  fail 'Meson documentation dependency binding is absent'

for tool in \
  build-html-docs.py check-html-docs.py install-html-docs.py \
  update-man-pages.sh check-html-manifest.py; do
  test -x "$root/tools/$tool" || fail "missing executable tools/$tool"
done
[ -s "$root/tools/canonicalize-man-roff.awk" ] || fail 'roff canonicalizer is absent'
[ ! -e "$root/tools/render-man-markdown.py" ] || fail 'retired scdoc-to-Markdown renderer remains'
[ ! -e "$root/tools/check-man-markdown.py" ] || fail 'retired scdoc-to-Markdown checker remains'

for helper in \
  ci/qualify-html-docs.sh ci/qualify-installed-documentation.py; do
  test -x "$root/$helper" || fail "missing executable $helper"
done

grep -F "input: 'generated/libpkgapply-posix.3'" "$root/docs/man/meson.build" >/dev/null ||
  fail 'ordinary man installation is not sourced from committed generated roff'
grep -F "'update-man-pages'" "$root/docs/man/meson.build" >/dev/null ||
  fail 'manual regeneration target is absent'
grep -F "'check-man-pages'" "$root/docs/man/meson.build" >/dev/null ||
  fail 'manual freshness target is absent'

if grep -RInE 'docs/(architecture|testing)\.md|architecture\.html' \
    "$root/README.md" "$root/DESIGN.md" "$root/TESTING.md" "$root/docs" "$root/tools" \
    >/dev/null 2>&1; then
  fail 'retired documentation authority path remains in active source'
fi

if grep -RInF '.scdoc' "$root/tools" --exclude='check_repository_contract.sh' >/dev/null 2>&1; then
  fail 'retired scdoc source handling remains in active tooling'
fi

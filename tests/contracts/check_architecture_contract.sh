#!/bin/sh
set -eu

root=$1
fail() {
  echo "architecture-contract: $*" >&2
  exit 1
}

if grep -R -E 'libpkgstate|pkgstate::|libpkgexec|pkgexec::' \
  "$root/include" "$root/src" >/dev/null
then
  fail 'foreign orchestration or state authority present'
fi

grep -F "subdir('src')" "$root/meson.build" >/dev/null || \
  fail 'library body not explicit'
grep -F "version: ['>=3.0.1', '<4.0.0']" "$root/meson.build" >/dev/null || \
  fail 'apply ABI-3 source-4 closure is absent'
grep -F "version: '>=0.4.0'" "$root/meson.build" >/dev/null || \
  fail 'image 0.4 floor absent'
grep -F "version: '>=0.3.0'" "$root/meson.build" >/dev/null || \
  fail 'plan 0.3 floor absent'

if grep -F 'fallback:' "$root/meson.build" >/dev/null; then
  fail 'repository fallback coupling present'
fi

grep -F 'libpkgapply_posix_consumer_deps = [' "$root/src/meson.build" >/dev/null || \
  fail 'public consumer closure is not explicit'
grep -F 'libpkgapply_dep,' "$root/src/meson.build" >/dev/null || \
  fail 'public apply dependency is absent'
grep -F 'libpkgimage_dep,' "$root/src/meson.build" >/dev/null || \
  fail 'public image dependency is absent'
grep -F "'libpkgplan >= 0.3.0'" "$root/src/meson.build" >/dev/null || \
  fail 'private planner closure is not explicit'
grep -F 'libcrypto_dep' "$root/src/meson.build" >/dev/null || \
  fail 'private crypto closure is not explicit'

grep -F 'libpkgapply_posix_sources = files(' "$root/src/meson.build" >/dev/null ||   fail 'production implementation source set is not explicit'
grep -F "'pkgapply-posix-test-implementation'" "$root/tests/meson.build" >/dev/null ||   fail 'private mechanism test target is absent'
grep -F 'libpkgapply_posix_internal_test_dep' "$root/tests/meson.build" >/dev/null ||   fail 'white-box tests do not have a private implementation dependency'

grep -F 'catch (const std::invalid_argument&)' \
  "$root/src/capture_store.cpp" >/dev/null ||
  fail 'capture-record canonical failures escape the provider domain'
grep -F 'private capture record contains invalid canonical values' \
  "$root/src/capture_store.cpp" >/dev/null ||
  fail 'capture-record canonical failure translation is absent'

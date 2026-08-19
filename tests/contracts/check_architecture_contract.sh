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
grep -F "version: ['>=4.0.0', '<5.0.0']" "$root/meson.build" >/dev/null || \
  fail 'apply ABI-4 append-only closure is absent'
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

# Generation 4 has one owner-authored semantic spine. The mutation backend may
# not retain the retired complete-journal/checkpoint publication vocabulary.
if grep -R -E 'application_restart_checkpoint|checkpoint_store|publish_journal|resumed_journal' \
  "$root/include" "$root/src" >/dev/null; then
  fail 'retired semantic checkpoint or complete-journal authority remains'
fi
grep -F 'public ::pkgapply::application_journal_store' \
  "$root/include/libpkgapply-posix/journal_store.h" >/dev/null ||
  fail 'POSIX journal store does not implement the owner storage interface'
grep -F 'encode_application_journal_declaration' "$root/src/journal_store.cpp" >/dev/null ||
  fail 'journal store does not use owner declaration encoding'
grep -F 'encode_application_journal_step' "$root/src/journal_store.cpp" >/dev/null ||
  fail 'journal store does not use owner step encoding'
grep -F 'encode_application_journal_cursor' "$root/src/journal_store.cpp" >/dev/null ||
  fail 'journal store does not use owner cursor encoding'
if grep -F 'encode_application_journal(' "$root/src/journal_store.cpp" >/dev/null; then
  fail 'journal store retained complete-snapshot encoding'
fi
if grep -E 'readdir|fdopendir|opendir|scandir|directory_iterator' \
  "$root/src/journal_store.cpp" >/dev/null; then
  fail 'journal store enumerates storage to discover authority'
fi
grep -F 'F_SETLKW' "$root/src/journal_store.cpp" >/dev/null ||
  fail 'cursor compare-and-publish lacks cross-process serialization'

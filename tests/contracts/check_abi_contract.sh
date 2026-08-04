#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

[ "$#" -eq 1 ] || {
  echo "usage: $0 SOURCE-ROOT" >&2
  exit 2
}
root=$1

fail()
{
  echo "abi-contract: $*" >&2
  exit 1
}

grep -F "soversion: '2'" "$root/src/meson.build" >/dev/null ||
  fail 'SONAME generation changed'
grep -F "gnu_symbol_visibility: 'hidden'" "$root/src/meson.build" >/dev/null ||
  fail 'hidden visibility is absent'
grep -F 'PKGAPPLY_POSIX_BUILDING_LIBRARY' "$root/src/meson.build" >/dev/null ||
  fail 'library export mode is absent'
grep -F '_ZN8pkgapply5posix*;' "$root/abi/libpkgapply-posix.exports" >/dev/null ||
  fail 'namespace export map is absent'

for header in "$root"/include/libpkgapply-posix/*.h; do
  case $(basename "$header") in
    export.h|version.h|libpkgapply-posix.h) continue ;;
  esac
  if grep -E '^class ' "$header" | grep -v 'PKGAPPLY_POSIX_API' >/dev/null; then
    fail "unannotated public class in ${header#"$root"/}"
  fi
done

for type in   target_mutation_lease_error   posix_backend_error   capture_store_error   checkpoint_store_error   rejected_store_error   journal_store_error   completed_evidence_store_error   target_observer_error   payload_stage_error
do
  grep -R -F "~$type() override;" "$root/include/libpkgapply-posix" >/dev/null ||
    fail "public exception destructor is not declared: $type"
  grep -R -F "~$type() = default;" "$root/src" >/dev/null ||
    fail "public exception vtable is not anchored: $type"
done

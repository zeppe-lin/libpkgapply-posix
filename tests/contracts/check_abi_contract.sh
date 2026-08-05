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

manifest=$root/abi/libpkgapply-posix.exports
generator=$root/tools/generate-elf-export-script.sh
surface_test=$root/tests/check_abi_surface.sh

[ -s "$manifest" ] || fail 'reviewed ELF ABI manifest is missing or empty'
[ -x "$generator" ] || fail 'ELF export-script generator is absent'
[ -x "$surface_test" ] || fail 'dynamic ABI surface audit is absent'

grep -F "soversion: '2'" "$root/src/meson.build" >/dev/null ||
  fail 'SONAME generation changed'
grep -F "gnu_symbol_visibility: 'hidden'" "$root/src/meson.build" >/dev/null ||
  fail 'hidden visibility is absent'
grep -F 'PKGAPPLY_POSIX_BUILDING_LIBRARY' "$root/src/meson.build" >/dev/null ||
  fail 'library export mode is absent'
grep -F 'generate-elf-export-script.sh' "$root/src/meson.build" >/dev/null ||
  fail 'reviewed ABI manifest is not converted into the linker script'
grep -F 'verify reviewed POSIX ABI surface' "$root/tests/meson.build" >/dev/null ||
  fail 'built shared-library ABI is not audited'

if grep -Ev '^_Z[A-Za-z0-9_]+$' "$manifest" >/dev/null; then
  fail 'ABI manifest contains a wildcard or invalid symbol'
fi

for symbol in \
  _ZN8pkgapply5posix27application_target_observer4openERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE \
  _ZNK8pkgapply5posix27application_target_observer7observeESt6vectorIN7pkgplan12package_pathESaIS4_EES2_INS0_27target_hardlink_expectationESaIS7_EE \
  _ZNK8pkgapply5posix21target_observer_error4codeEv
 do
  grep -Fx "$symbol" "$manifest" >/dev/null ||
    fail "required target-observer ABI symbol is absent: $symbol"
 done

for header in "$root"/include/libpkgapply-posix/*.h; do
  case $(basename "$header") in
    export.h|version.h|libpkgapply-posix.h) continue ;;
  esac
  if grep -E '^class ' "$header" | grep -v 'PKGAPPLY_POSIX_API' >/dev/null; then
    fail "unannotated public class in ${header#"$root"/}"
  fi
done

for type in \
  target_mutation_lease_error \
  posix_backend_error \
  capture_store_error \
  checkpoint_store_error \
  rejected_store_error \
  journal_store_error \
  completed_evidence_store_error \
  target_observer_error \
  payload_stage_error
 do
  grep -R -F "~$type() override;" "$root/include/libpkgapply-posix" >/dev/null ||
    fail "public exception destructor is not declared: $type"
  grep -R -F "~$type() = default;" "$root/src" >/dev/null ||
    fail "public exception vtable is not anchored: $type"
 done

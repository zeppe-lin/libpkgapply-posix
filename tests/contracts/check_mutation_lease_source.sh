#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
fail(){ echo "posix-mutation-lease-source-test: $*" >&2; exit 1; }
header=$root/include/libpkgapply-posix/mutation_lease.h
source=$root/src/mutation_lease.cpp
for file in "$header" "$source"; do [ -s "$file" ] || fail "missing or empty ${file#"$root"/}"; done
for contract in \
  'const application_target_context& target' \
  'int lock_directory_fd' \
  'lock_busy' \
  'bool held() const noexcept override'
do
  grep -F "$contract" "$header" >/dev/null || fail "installed lease API omits $contract"
done
for contract in \
  'F_DUPFD_CLOEXEC' \
  'O_NOFOLLOW' \
  'LOCK_EX | LOCK_NB' \
  'AT_SYMLINK_NOFOLLOW' \
  'RAND_bytes' \
  'mutation_exclusion_domain()'
do
  grep -F "$contract" "$source" >/dev/null || fail "lease mechanism omits $contract"
done
if grep -E 'LOCK_SH|sleep\(|usleep\(|nanosleep\(|::unlink\(|::remove\(' "$source" >/dev/null; then
  fail 'lease mechanism acquired read locks, waited, or removed authority'
fi
if grep -E '#include <libpkgstate|application_posix_backend|application_target_observer' "$source" "$header" >/dev/null; then
  fail 'lease mechanism absorbed state, backend, or observation authority'
fi
grep -F "['mutation-lease', 'mechanism/posix_mutation_lease_test.cpp'" \
  "$root/tests/meson.build" >/dev/null ||
  fail 'Meson qualification omits the mutation-lease mechanism case'
grep -F "'mutation_lease.h'," "$root/tests/meson.build" >/dev/null ||
  fail 'Meson public-header list omits mutation_lease.h'
grep -F "test('header-' + header.underscorify(), target, suite: 'header')" \
  "$root/tests/meson.build" >/dev/null ||
  fail 'Meson does not register generic standalone headers in the header suite'

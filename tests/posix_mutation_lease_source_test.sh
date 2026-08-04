#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu
root=$1

fail()
{
  echo "posix-mutation-lease-source-test: $*" >&2
  exit 1
}

header=$root/include/libpkgapply-posix/mutation_lease.h
source=$root/posix/mutation_lease.cpp
model=$root/include/libpkgapply/mutation_lease.h

for file in "$header" "$source" "$model"; do
  test -s "$file" || fail "missing or empty ${file#"$root"/}"
done

for contract in \
  'mutation_lease_acquisition' \
  'mutation_lease_nonce' \
  'application_target_context_identity target' \
  'mutation_exclusion_domain_identity exclusion_domain'
do
  grep -F "$contract" "$model" >/dev/null ||
    fail "core acquisition model omits $contract"
done

for contract in \
  'const application_target_context& target' \
  'int lock_directory_fd' \
  'lock_busy' \
  'bool held() const noexcept override'
do
  grep -F "$contract" "$header" >/dev/null ||
    fail "installed POSIX lease API omits $contract"
done

for contract in \
  'F_DUPFD_CLOEXEC' \
  'O_NOFOLLOW' \
  'LOCK_EX | LOCK_NB' \
  'AT_SYMLINK_NOFOLLOW' \
  'RAND_bytes' \
  'mutation_exclusion_domain()'
do
  grep -F "$contract" "$source" >/dev/null ||
    fail "POSIX lease mechanism omits $contract"
done

if grep -E 'LOCK_SH|sleep\(|usleep\(|nanosleep\(|::unlink\(|::remove\(' \
    "$source" >/dev/null; then
  fail 'POSIX lease mechanism acquired read locks, waited, or removed authority'
fi

if grep -E '#include <libpkgstate|application_posix_backend|application_target_observer' \
    "$source" "$header" >/dev/null; then
  fail 'POSIX lease mechanism absorbed state, backend, or target-observation authority'
fi

for contract in \
  'posix-mutation-lease-header-test' \
  'posix-mutation-lease-test'
do
  grep -F "$contract" "$root/tests/meson.build" >/dev/null ||
    fail "Meson qualification omits $contract"
done

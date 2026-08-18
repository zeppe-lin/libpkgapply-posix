#!/bin/sh
set -eu
root=$1
fail(){ echo "active-namespace-source: $*" >&2; exit 1; }

source=$root/src/active_namespace.cpp
header=$root/src/active_namespace.h
stress=$root/tests/mechanism/posix_active_incoming_test.cpp

grep -F 'struct dirty_filesystem_authority final' "$header" >/dev/null ||
  fail 'filesystem-level durability authority is absent'
grep -F 'dirty_filesystems_' "$header" >/dev/null ||
  fail 'dirty filesystem authority set is absent'
if grep -F 'dirty_descriptors_' "$header" "$source" >/dev/null; then
  fail 'active durability regressed to one retained descriptor per path'
fi
grep -F '::syncfs(descriptor)' "$source" >/dev/null ||
  fail 'Linux filesystem durability barrier is absent'
grep -F 'synchronize_filesystem(authority.descriptor)' "$source" >/dev/null ||
  fail 'dirty filesystem authority does not reach the durability barrier'
grep -F 'retain_dirty_filesystem(workspace.parent_descriptor())' "$source" >/dev/null ||
  fail 'namespace mutation does not bind its touched filesystem'
grep -F 'RLIMIT_NOFILE' "$stress" >/dev/null ||
  fail 'active descriptor-pressure witness is absent'
grep -F 'constexpr std::size_t stress_count = 96U;' "$stress" >/dev/null ||
  fail 'active descriptor-pressure witness is too small'
grep -F 'active durability consumes one live descriptor per mutated path' "$stress" >/dev/null ||
  fail 'active descriptor-pressure refusal is not explicit'

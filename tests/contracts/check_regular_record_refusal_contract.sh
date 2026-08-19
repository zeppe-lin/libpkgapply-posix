#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
root=$1
fail(){ echo "regular-record-refusal-contract: $*" >&2; exit 1; }

for file in \
  src/journal_store.cpp \
  src/completed_evidence_store.cpp \
  src/payload_stage.cpp \
  src/capture_store.cpp \
  src/rejected_store.cpp
do
  [ -s "$root/$file" ] || fail "missing $file"
done

# Regular-file authority must never block on a special file before fstat/type
# validation. Directory opens are intentionally outside this check.
if grep -F 'O_RDONLY | cloexec_flag() | nofollow_flag()));' \
     "$root/src/completed_evidence_store.cpp" \
     "$root/src/payload_stage.cpp" >/dev/null; then
  fail 'blocking regular-file open remains in flag-helper stores'
fi
if grep -F 'O_RDONLY | O_CLOEXEC | O_NOFOLLOW));' \
     "$root/src/capture_store.cpp" "$root/src/rejected_store.cpp" >/dev/null; then
  fail 'blocking regular-file open remains in capture/rejected stores'
fi
grep -F 'O_RDONLY | cloexec_flag() | nofollow_flag() | O_NONBLOCK' \
  "$root/src/journal_store.cpp" >/dev/null || fail 'journal retained-value open is blocking'
grep -F 'O_NONBLOCK' "$root/src/completed_evidence_store.cpp" >/dev/null || fail 'completed-evidence record open is blocking'
[ "$(grep -c 'O_NONBLOCK' "$root/src/payload_stage.cpp")" -ge 3 ] || fail 'payload-stage regular opens are not all nonblocking'
[ "$(grep -c 'O_NONBLOCK' "$root/src/capture_store.cpp")" -ge 3 ] || fail 'capture regular opens are not all nonblocking'
[ "$(grep -c 'O_NONBLOCK' "$root/src/rejected_store.cpp")" -ge 3 ] || fail 'rejected regular opens are not all nonblocking'

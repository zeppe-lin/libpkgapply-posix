# Contributing

## Boundary first

Changes may implement POSIX observation, staging, durable byte persistence,
mutation, recovery, and backend composition. They must not move plan
construction, semantic admission, installed-state publication, lifecycle
execution, path selection, semantic journal encoding, or package-manager policy
into this repository.

A new mechanism must state its selected authority, descriptor lifetime,
write-ahead rule, synchronization domain, restart behavior, refusal categories,
and exact evidence returned to `libpkgapply`.

For journal work, the owner codec is `libpkgapply`. This repository may store
and retrieve canonical bytes but must not decode a competing semantic format,
reconstruct a complete journal from filesystem residue, or introduce another
restart checkpoint.

## Engineering standard

Follow `docs/code-style.md`. Preserve typed failures and descriptor anchoring.
Public declarations require Doxygen and explicit export annotation. OpenSSL and
system-call details remain private.

## Tests and patches

Add focused hostile behavior tests plus source, metadata, installation, and ABI
qualification when a boundary changes. Prefer deterministic operation/byte
counts over wall-clock claims. Keep extraction history immutable. Every patch
must pass `git diff --check`.

# Contributing

## Boundary first

Changes may implement POSIX observation, staging, persistence, mutation,
recovery, and backend composition. They must not move plan construction,
semantic admission, installed-state publication, lifecycle execution, path
selection, or package-manager policy into this repository.

A new mechanism must state its selected authority, descriptor lifetime,
write-ahead rule, synchronization domain, restart behavior, refusal categories,
and exact evidence returned to `libpkgapply`.

## Engineering standard

Follow `docs/code-style.md`. Preserve typed failures and descriptor anchoring.
Public declarations require Doxygen and explicit export annotation. OpenSSL and
system-call details remain private.

## Tests and patches

Add focused behavior tests plus source, metadata, installation, and ABI
qualification when the public boundary changes. Keep extraction, semantic
changes, generated material, and repository policy separate where practical.
Every patch must pass `git diff --check`.

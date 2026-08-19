# History

## 4.0.0

- Removed the provider-owned restart-checkpoint store and complete-journal snapshot persistence. The POSIX provider now has one separate `application_journal_store` implementing the libpkgapply generation-4 declaration/immutable-step/bounded-cursor storage interface.
- Made the mutation backend physically independent of semantic journal persistence: backend construction no longer accepts journal/checkpoint descriptors, backend transactions reject the journal synchronization domain, and restart consumes only the owner-derived ephemeral `application_restart_view`.
- Persist canonical journal bytes exclusively through libpkgapply's owner transport codec. Immutable declaration/step publication is no-replace; cursor compare-and-publish is serialized across processes and supports exact idempotent retry after uncertain directory durability.
- Added direct request-to-declaration restart routing without directory scans, immutable conflict/stale-CAS/corruption/FIFO attacks, constrained-`RLIMIT_NOFILE` stress, and exact byte accounting that rejects any hidden snapshot/checkpoint history.
- Advanced the provider ABI to `libpkgapply-posix.so.3`, API generation 3, and bound the public closure to `libpkgapply >= 4.0.0, < 5.0.0`. No generation-2 compatibility adapter is retained.

## 3.2.3

- Bound active-namespace durability descriptor retention by touched filesystem
  rather than mutated path. The mechanism retains at most one representative
  descriptor per observed `st_dev` and uses one filesystem durability barrier
  per retained authority, so large package application no longer exhausts the
  supervisor descriptor table before final synchronization.
- Preserve deferred durability and exact retry semantics: failed filesystem
  barriers retain their descriptor authorities, while successful barriers clear
  them only after every touched filesystem is confirmed. No current package path
  is reopened to reconstruct durability authority.
- Add a constrained-`RLIMIT_NOFILE` witness publishing 96 active paths and
  require the complete operation to synchronize under a 48-descriptor soft
  limit.
- Preserve `libpkgapply-posix.so.2` and API generation 2; no public layout,
  identity domain, durable encoding, planner/application semantics, or state
  vocabulary changes.

## 3.2.2

- Bound reopened old-object capture descriptor retention by live application
  attempt rather than captured-object count. Captures from one exact attempt now
  share one descriptor-anchored attempt-directory authority while preserving
  independent immutable capture records and on-demand payload verification.
- Add a constrained-`RLIMIT_NOFILE` mechanism witness retaining 96 captures from
  one attempt, preventing small synthetic packages from hiding descriptor
  cardinality regressions.
- Preserve `libpkgapply-posix.so.2` and API generation 2; no public layout,
  identity domain, durable encoding, or capture semantics change.

## 3.2.1

- Close the POSIX provider on the source-ABI-4 application authority.
- Require `libpkgapply >= 3.0.1, < 4.0.0`, excluding application 3.0.0
  whose admitted build-plan interval could still select source ABI 3.
- Qualify application fixtures against `libpkgbuild-image >= 1.0.1`, the
  resolver-4-bound image admission release.
- Preserve `libpkgapply-posix.so.2` and API generation 2; this is a dependency
  closure release, not a POSIX ABI change.

## 3.2.0

- Refuse FIFO and other non-regular corruption in private/durable regular-file
  authority slots without blocking before type validation.
- Align maintained Markdown on ATX headings and qualify against the published
  resolver 3.0 / apply 3.0 release closure.
- Made rejected-object record identity a direct provider-owned reopening key.
- Added self-contained identity reopening without reconstructing planner commands
  or requiring retained application-journal authority.
- Published regular payload index authority before the record selector and repair
  the index on exact rejected-object republication after interrupted publication.
- Translate malformed canonical capture records back into the provider-owned
  `capture_store_error` domain instead of leaking semantic constructor errors.
- Qualify the provider against `libpkgapply` ABI generation 3 and the current
  source, catalog, state, planner, and source-plan owner generations.
- Kept request-bound restart loading unchanged and preserved
  `libpkgapply-posix.so.2` / API generation 2 as an additive release.

## 3.1.0

- Keep direct incoming regular rejected-object evidence publication-complete
  when no hard-link peer relation is asserted.
- Added a descriptor-anchored direct request-to-journal restart index.
- Published the index only after the referenced journal snapshot is durable.
- Kept attempt selection and journal discovery outside the mechanism provider;
  missing or contradictory index authority fails closed.
- Preserved `libpkgapply-posix.so.2` and API generation 2 with one additive
  journal-store lookup method.

## 3.0.0

- Extracted the existing `libpkgapply-posix.so.2` product from
  `libpkgapply` 2.3.0.
- Preserved the published POSIX ABI generation while establishing independent
  repository and release ownership.
- Made direct public dependencies on `libpkgapply` and `libpkgimage`
  explicit; retained direct planner use and OpenSSL as private implementation
  requirements.
- Added hidden-by-default visibility, explicit API exports, repository
  contracts, installed-consumer qualification, and independent CI.
- Reviewed the complete public C++ RTTI and vtable surface and added a
  link consumer covering every exported polymorphic type.
- Anchored every public POSIX exception domain with an out-of-line owner
  destructor.
- Published complete mutation-lease, target-observation, and composed-backend
  contracts, including descriptor authority, error domains, and restart binding.
- Published complete incoming-payload, old-object capture, and rejected-object
  store contracts, including private namespace, byte verification, and durability
  refusal semantics.
- Published complete durable-journal, restart-checkpoint, completed-evidence,
  umbrella, and version contracts, including atomic visibility and exact
  republication semantics.
- Updated package-plan fixtures to the syntax-neutral `libpkgsource` 3.0 sealing contract.

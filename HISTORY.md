# History

## 3.2.0

- Made rejected-object record identity a direct provider-owned reopening key.
- Added self-contained identity reopening without reconstructing planner commands
  or requiring retained application-journal authority.
- Published regular payload index authority before the record selector and repair
  the index on exact rejected-object republication after interrupted publication.
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

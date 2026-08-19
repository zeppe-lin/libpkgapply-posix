# Qualification

Generation 4 qualification is contract-first and adversarial.

## Journal persistence

The journal-store mechanism must prove:

- immutable declaration publication and exact canonical retry;
- immutable step publication and conflicting same-sequence refusal;
- a durable orphan step does not advance the cursor;
- stale cursor compare-and-publish is refused;
- exact desired-cursor retry succeeds after uncertain publication;
- direct request locator resolves one exact declaration and validates its
  request binding;
- pathname replacement cannot redirect an already-open store;
- symlink/special-file corruption is refused without blocking;
- constrained `RLIMIT_NOFILE` does not make descriptor use grow with step count;
- total regular-file journal bytes equal exactly one declaration, immutable
  steps, and the current bounded cursor; the cursor lock has zero payload bytes;
- no checkpoint store or complete journal snapshot exists.

These are deterministic operation and byte-volume properties. Wall-clock
thresholds may detect gross regressions but are not the authority.

## Backend integration

Integration must compose a real POSIX backend with a separate POSIX journal
store through public `pkgapply::apply()` and `pkgapply::resume_application()`.
A crash witness interrupts after the owner commits an active intent and before
the physical actuator is invoked. Restart must use the exact retained
declaration, derive replay state from owner history, reopen the POSIX physical
attempt, recover according to core policy, and not replay the unresolved
actuator.

Backend construction itself must perform no observation, staging, mutation,
journal publication, or evidence publication. Descriptor anchoring is proved by
renaming the selected target/store path after construction and observing that
the retained object, not the replacement pathname, remains authoritative.

## Durability and failure

Payload, recovery/active namespace, rejected storage, and completed-evidence
synchronization failures retain their typed mechanism evidence. The mutation
backend must reject the journal durability domain; successful journal-store
publication is journal durability authority.

## Product gates

Release qualification includes:

- GCC/Clang shared and static builds with warnings as errors;
- GCC/Clang ASan+UBSan runs;
- every public header compiled independently;
- exact reviewed ELF exports and no `pkgapply::posix::detail` leakage;
- provider SONAME 3 and direct `NEEDED libpkgapply.so.4` in shared builds;
- installed shared/static consumers through pkg-config only;
- public Doxygen and HTML/manual freshness contracts;
- clean mailbox replay and exact tree comparison.

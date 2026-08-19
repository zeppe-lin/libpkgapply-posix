# Maintaining libpkgapply-posix

## Dependency discipline

Release against compatible published `libpkgapply`, `libpkgimage`, and
`libpkgplan` tags. Generation 4 requires `libpkgapply >= 4.0.0, < 5.0.0`.
Public pkg-config requirements must match installed-header exposure exactly;
direct planner use and `libcrypto` remain private.

## Mechanism discipline

A storage change must state selected authority, descriptor lifetime, crash
points, idempotence, publication visibility, and corruption refusal. A pathname
is never retained as authority when a descriptor can bind the selected object.

The append-only journal is especially strict: POSIX owns only durable opaque
bytes and exact-name indexing. Do not add a semantic codec, complete-journal
snapshot, directory scan, provider checkpoint, or history reconstruction here.
The cursor CAS must remain cross-process serialized; immutable declarations and
steps must remain no-replace.

Restart views are ephemeral owner projections. They may revalidate subordinate
physical evidence but must never be persisted as a new authority.

## Release checklist

1. Build GCC and Clang shared/static closures with warnings as errors.
2. Run the complete behavior suite and ASan/UBSan jobs.
3. Compile every installed header independently.
4. Qualify installed shared/static consumers through pkg-config only.
5. Inspect SONAME, `NEEDED`, symbol versions, and exact exports; reject private
   `pkgapply::posix::detail` symbols.
6. Prove the journal store has no complete snapshot/checkpoint files and total
   bytes grow only with declaration + immutable steps + bounded cursor.
7. Prove restart uses owner history and direct exact-name lookup, not directory
   enumeration or current-target reconstruction.
8. Confirm white-box tests link only the private implementation target.
9. Lint/regenerate the manual and documentation.
10. Replay the release mailbox independently and compare the final tree.

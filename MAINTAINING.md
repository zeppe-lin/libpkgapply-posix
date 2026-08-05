# Maintaining libpkgapply-posix

## Dependency discipline

Release against compatible published `libpkgapply`, `libpkgimage`, and
`libpkgplan` tags. Public pkg-config requirements must match installed-header
exposure exactly; direct planner use and `libcrypto` remain private.

## Mechanism discipline

Storage protocols are durable mechanism contracts. A format or synchronization
change must define compatibility, crash points, idempotence, quarantine,
garbage collection, and migration. A pathname is never a retained authority
when a descriptor can bind the selected object.

## Release checklist

1. Build GCC and Clang shared and static closures with warnings as errors.
2. Run the complete behavior suite and ASan/UBSan jobs.
3. Compile every installed header independently.
4. Qualify installed shared and static consumers through pkg-config only.
5. Inspect SONAME, `NEEDED`, symbol versions, and the exact exported inventory;
   confirm no `pkgapply::posix::detail` symbol is exported.
6. Confirm white-box mechanism tests link the private implementation target,
   while public and installed consumers link only the product library.
7. Confirm no non-POSIX policy entered the repository and no POSIX mechanics
   remain in `libpkgapply`.
8. Lint and stage the manual and project documentation.
9. Replay the release mailbox independently and compare the final tree.

# Integration

A caller selects the target root and private storage directories, acquires a
`pkgapply::posix::target_mutation_lease`, constructs
`application_posix_backend` from already-open directory descriptors, and hands
both to `libpkgapply`.

The public metadata exposes `libpkgapply >= 3.0.1, < 4.0.0` and
`libpkgimage >= 0.4.0` because installed headers use those value types directly.
Direct `libpkgplan >= 0.3.0` use and `libcrypto` remain private implementation
requirements and enter consumer flags only for static linkage.

The qualified shared closure binds `libpkgapply >= 3.0.1, < 4.0.0` to semantic-core ABI
generation 3 (`libpkgapply.so.3`). `libpkgapply-posix.so.2` remains the provider
ABI generation; callers must clean-rebuild the provider when replacing the
pre-release core object so its dynamic dependency names the corrected core
SONAME.

Repository separation is intentional. A non-POSIX backend may implement the
same `libpkgapply` contracts without inheriting POSIX storage layout, system
calls, or failure categories. Rejected-object record identity becomes a direct
reopening key only because this provider explicitly indexes and validates it;
consumers must not derive or scan the private POSIX storage layout. Conversely,
POSIX mechanism changes can be reviewed without touching semantic application
policy.

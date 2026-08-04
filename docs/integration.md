# Integration

A caller selects the target root and private storage directories, acquires a
`pkgapply::posix::target_mutation_lease`, constructs
`application_posix_backend` from already-open directory descriptors, and hands
both to `libpkgapply`.

The public metadata exposes `libpkgapply >= 3.0.0` and
`libpkgimage >= 0.4.0` because installed headers use those value types directly.
Direct `libpkgplan >= 0.3.0` use and `libcrypto` remain private implementation
requirements and enter consumer flags only for static linkage.

Repository separation is intentional. A non-POSIX backend may implement the
same `libpkgapply` contracts without inheriting POSIX storage layout, system
calls, or failure categories. Conversely, POSIX mechanism changes can be
reviewed without touching semantic application policy.

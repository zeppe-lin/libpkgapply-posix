# ELF ABI policy

The independent 3.0.0 release preserves `libpkgapply-posix.so.2`. The SONAME
belongs to the already-published in-tree POSIX ABI generation; repository
extraction does not manufacture an ABI break.

Public classes carry `PKGAPPLY_POSIX_API`. Compilation is hidden by default and
an ELF version script permits only the `pkgapply::posix` mangling domain. This
prevents active-namespace helpers, workspace helpers, OpenSSL internals, and
standard-library implementation bodies from becoming accidental ABI.

The namespace manifest is intentionally broader than a per-symbol freeze until
a native build of the extracted repository can produce and review its exact
symbol inventory. Before the first independent tag, maintainers must capture
that inventory from both GCC and Clang shared builds and either narrow the map
or record the accepted set in this document. No symbol list has been invented
without a linkable dependency closure.

Public headers expose `libpkgapply` and `libpkgimage` value types directly;
those dependencies belong in pkg-config `Requires`. Direct `libpkgplan` use is
an implementation edge, while `libcrypto` is a private mechanism provider.
Both belong in `Requires.private` and enter consumer flags only for static
linkage.

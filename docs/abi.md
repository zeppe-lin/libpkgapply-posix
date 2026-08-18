# ELF ABI policy

The additive 3.2.2 release preserves `libpkgapply-posix.so.2`. The SONAME
belongs to the already-published in-tree POSIX ABI generation; repository
extraction does not manufacture an ABI break.

`libpkgapply` 3.0.1 is semantic-core ABI generation 3 and is linked as
`libpkgapply.so.3`. That dependency transition does not by itself advance the
provider SONAME: the POSIX callable/RTTI surface remains the reviewed additive
generation-2 surface, and the core polymorphic interfaces inherited by the
provider retain their virtual protocol shape. Shared-boundary qualification
therefore requires provider SONAME 2 together with semantic-core NEEDED entry
`libpkgapply.so.3`.

The published 3.0 semantic core changes the by-value
`application_journal_record` layout so its header retains the complete admitted
lease-bound state projection. POSIX journal-store entry points consume and
return that core value, so providers built against obsolete pre-release 3.0
development layouts are not compatible merely because they named the same core
SONAME. Release qualification rebuilds against published `libpkgapply` 3.0.1;
there is no compatibility shim for abandoned development layouts. That closure
rebuild does not by itself advance the provider SONAME.

Public classes carry `PKGAPPLY_POSIX_API`. Compilation is hidden by default and
an exact reviewed ELF manifest is converted into the linker version script.
The manifest contains the installed callable surface and the required public
RTTI, type-name, and vtable anchors. It excludes the private
`pkgapply::posix::detail` namespace, OpenSSL internals, and standard-library
implementation bodies.

White-box active-namespace and workspace tests include non-installed headers.
They link a private, non-installed static test library built from the same
production source list. They do not consume the installed shared object and do
not justify exporting implementation symbols. Public-consumer tests and the
installed consumer link only through `libpkgapply-posix` and its pkg-config
metadata.

Public headers expose `libpkgapply` and `libpkgimage` value types directly;
those dependencies belong in pkg-config `Requires`. Direct `libpkgplan` use is
an implementation edge, while `libcrypto` is a private mechanism provider.
Both belong in `Requires.private` and enter consumer flags only for static
linkage.

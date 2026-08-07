# ELF ABI policy

The additive 3.1.0 release preserves `libpkgapply-posix.so.2`. The SONAME
belongs to the already-published in-tree POSIX ABI generation; repository
extraction does not manufacture an ABI break.

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

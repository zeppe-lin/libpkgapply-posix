# ABI policy

`libpkgapply-posix` 4.0.0 advances the provider ABI to
`libpkgapply-posix.so.3` and requires semantic core generation 4
(`libpkgapply.so.4`).

The break is intentional. The provider no longer exposes complete-journal
publication or restart-checkpoint storage, `application_posix_backend` no longer
accepts journal/checkpoint descriptors, and backend resume consumes the
owner-derived `application_restart_view`. A new public
`pkgapply::posix::application_journal_store` implements the separate
`libpkgapply::application_journal_store` persistence interface.

There is no compatibility shim for provider generation 2. Old toolchains may
continue to use their old provider/core closure.

Public classes carry `PKGAPPLY_POSIX_API`. Compilation is hidden by default and
an exact reviewed ELF manifest is converted into the linker version script.
The manifest contains installed callable symbols plus required public RTTI,
type-name, and vtable anchors. It excludes `pkgapply::posix::detail`, OpenSSL
internals, and standard-library implementation bodies.

White-box mechanism tests link a private non-installed static target built from
the production source set. Public and installed consumers link only through the
product library and pkg-config metadata.

Installed headers expose `libpkgapply` and `libpkgimage` types directly, so both
are public pkg-config requirements. `libpkgplan` and `libcrypto` are private
implementation dependencies and enter consumer flags only for static linkage.

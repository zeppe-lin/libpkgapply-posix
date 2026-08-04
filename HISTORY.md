# History

## 3.0.0

- Extracted the existing `libpkgapply-posix.so.2` product from
  `libpkgapply` 2.3.0.
- Preserved the published POSIX ABI generation while establishing independent
  repository and release ownership.
- Made direct public dependencies on `libpkgapply`, `libpkgimage`, and
  `libpkgplan` explicit; retained OpenSSL as a private provider.
- Added hidden-by-default visibility, explicit API exports, repository
  contracts, installed-consumer qualification, and independent CI.

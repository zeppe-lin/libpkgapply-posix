# History

## 3.0.0

- Extracted the existing `libpkgapply-posix.so.2` product from
  `libpkgapply` 2.3.0.
- Preserved the published POSIX ABI generation while establishing independent
  repository and release ownership.
- Made direct public dependencies on `libpkgapply` and `libpkgimage`
  explicit; retained direct planner use and OpenSSL as private implementation
  requirements.
- Added hidden-by-default visibility, explicit API exports, repository
  contracts, installed-consumer qualification, and independent CI.
- Anchored every public POSIX exception domain with an out-of-line owner
  destructor.
- Published complete mutation-lease, target-observation, and composed-backend
  contracts, including descriptor authority, error domains, and restart binding.

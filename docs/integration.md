# Integration

A controller selects the managed target and five mechanism directories for the
POSIX backend: target root, payload store, capture store, rejected store, and
completed-evidence store. It constructs `application_posix_backend` from those
open descriptors.

Journal persistence is wired separately:

```cpp
auto journal = pkgapply::posix::application_journal_store::open(journal_path);
auto backend = pkgapply::posix::application_posix_backend::from_directory_fds(
    target, target_fd, payload_fd, capture_fd, rejected_fd, completed_fd);

auto receipt = pkgapply::apply(
    request, state, lease, *backend, *journal, archive);
```

On restart the controller resolves the exact declaration through its retained
identity or the POSIX store's direct request locator, reacquires a current
mutation lease/state projection, and calls `pkgapply::resume_application()`.
`libpkgapply` loads declaration/steps/cursor, validates the owner chain, derives
an ephemeral restart view, and only then asks the POSIX backend to reopen
subordinate physical evidence.

The provider never scans the journal namespace to choose a newest attempt. The
request locator is mutable routing metadata and is validated against the exact
referenced declaration before use.

Public metadata exposes `libpkgapply >= 4.0.0, < 5.0.0` and
`libpkgimage >= 0.4.0`. Direct `libpkgplan >= 0.3.0` use and `libcrypto` remain
private. The qualified shared closure is `libpkgapply-posix.so.3` with a direct
`NEEDED libpkgapply.so.4` edge.

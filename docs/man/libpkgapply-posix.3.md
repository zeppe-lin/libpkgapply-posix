% LIBPKGAPPLY-POSIX(3) libpkgapply-posix | Version 4.0.0


# NAME

libpkgapply-posix - descriptor-anchored POSIX application mechanisms

# SYNOPSIS

```
#include <libpkgapply-posix/libpkgapply-posix.h>

auto journal = pkgapply::posix::application_journal_store::open(
    journal_directory);

auto backend =
    pkgapply::posix::application_posix_backend::from_directory_fds(
        target,
        target_root_fd,
        payload_store_fd,
        capture_store_fd,
        rejected_store_fd,
        completed_evidence_store_fd);

auto receipt = pkgapply::apply(
    request, state, lease, *backend, *journal, archive);
```

# DESCRIPTION

**libpkgapply-posix** provides the reference POSIX mechanisms for
**libpkgapply**. The mutation backend and application journal store are separate
objects. The backend owns physical observation, staging, capture, mutation,
recovery and evidence stores. The journal store owns only exact-name durable
publication of canonical bytes encoded by **libpkgapply**.

Caller-selected directory descriptors are duplicated and retained. Replacing a
pathname after construction cannot redirect a live backend or journal store.
The provider does not discover target identity, package plans, leases, storage
locations, or package-manager policy from ambient state.

# JOURNAL STORE

**application_journal_store** implements the core append-only storage interface.
It persists one immutable declaration, immutable sequence-addressed steps, and
one bounded cursor per declaration. It also maintains a direct mutable
request-to-declaration locator used only for restart routing.

Declarations and steps are synchronized and published without replacement.
Publishing different bytes under an occupied immutable address fails.
Cursor replacement is serialized across processes with an advisory lock and is
performed as compare-and-publish followed by atomic replacement and directory
synchronization. Exact retry of an already-visible desired cursor is idempotent.

The store performs exact-name lookup only. It does not enumerate journal
directories to discover history and has no complete-journal or restart-checkpoint
format.

# TARGET MUTATION LEASE

**target_mutation_lease::acquire()** binds one caller-selected lock directory,
target context and mutation-exclusion domain. Acquisition is nonblocking; a
competing live holder is reported as **lock_busy**. The caller retains the lease
through application/state publication/finalization according to controller
policy.

# BACKEND DESCRIPTORS

**application_posix_backend::from_directory_fds()** accepts, in order:

- managed target root;
- private incoming-payload store;
- private old-object capture store;
- immutable rejected-object store; and
- immutable completed-evidence store.

Journal persistence is not a backend descriptor. The separate journal store is
passed directly to **pkgapply::apply()** and **pkgapply::resume_application()**.

# RESTART

A controller resumes by retaining or resolving the exact journal declaration
identity, acquiring a current lease/state projection, and calling
**pkgapply::resume_application()** with the backend and journal store.

**libpkgapply** validates declaration, immutable step chain and cursor before it
constructs an ephemeral **application_restart_view**. The POSIX backend uses
that view to revalidate only subordinate physical payload, capture, rejected,
active/recovery, durability and completed-evidence facts. It cannot publish a
missing semantic terminal result from provider residue.

The direct **load_active_declaration()** locator follows one exact request index
and validates the referenced declaration/request binding. It does not select a
newest attempt by scanning storage.

# DURABILITY

Journal durability is established by successful journal-store publication.
**application_backend_transaction::synchronize(journal)** is rejected.
Incoming staging, recovery staging, active namespace, rejected storage and
completed-evidence durability remain physical backend domains.

# ERRORS

**journal_store_error** distinguishes directory/value I/O, corruption,
immutable conflicts, stale cursor conflicts, index corruption and cursor-lock
failure. **publication_visible()** reports failures after candidate bytes may
already have become visible, allowing exact idempotent retry.

**posix_backend_error** reports invalid descriptors, target/lease/request/image
binding failures, nonce generation failure and contradictory owner-derived
restart authority. Other mechanisms retain their own typed error domains.

# CLEANUP

Transaction destruction closes live descriptors and abandons incomplete private
construction. Durable owner journal steps and subordinate evidence are not
deleted merely because current filesystem residue appears unused. Garbage
collection requires explicit higher-level authority.

# SEE ALSO

**libpkgapply**(3), **pkgapply**(7)

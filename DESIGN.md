# libpkgapply-posix design

## Role

`libpkgapply-posix` owns concrete POSIX mechanisms for the semantic application
engine in `libpkgapply`.

```text
libpkgapply request / declaration / immutable steps / cursor
                         |
              canonical owner transport bytes
                         |
                         v
               libpkgapply-posix journal store
                         |
             exact-name POSIX persistence

libpkgapply semantic effect selection
                         |
                         v
               libpkgapply-posix backend
    observation / staging / capture / mutation / recovery
                         |
                         v
             caller-selected POSIX authorities
```

The journal store and mutation backend may live in the same package, but they
are separate objects with separate authority. The mutation transaction cannot
publish semantic history or synchronize the journal domain.

## Owned mechanisms

The library owns:

- FD-anchored target observation;
- caller-held target mutation leases;
- attempt-bound incoming payload staging;
- pre-mutation old-object capture;
- immutable rejected-object publication and direct record-identity reopening;
- immutable completed-evidence publication;
- active namespace mutation and recovery;
- descriptor-anchored exact-name journal byte persistence; and
- composition of physical mechanisms as `application_posix_backend`.

The journal mechanism provides immutable declaration/step publication, a
cross-process serialized compare-and-publish cursor, and a direct mutable
request-to-declaration locator. The locator is restart routing metadata, not
semantic history.

## Non-ownership

The library does not own semantic identities or journal wire formats received
from `libpkgapply`, `libpkgplan`, or `libpkgimage`. Journal values are encoded
and decoded only by `libpkgapply`'s canonical transport codec. POSIX storage
validates exact addressing and physical file properties around those bytes.

There is no provider-owned restart-checkpoint aggregate or codec. On restart,
`libpkgapply` rehydrates owner history and passes an ephemeral
`application_restart_view`; the backend uses that view only to reopen and
revalidate subordinate payload, capture, rejected, active/recovery, durability,
and completed-evidence mechanisms.

Every pathname-taking factory selects and opens authority once. Long-lived
objects retain duplicated descriptors so pathname replacement cannot redirect
an admitted store or transaction.

OpenSSL is a private provider used for hashing and nonce material. No OpenSSL
type appears in the installed API.

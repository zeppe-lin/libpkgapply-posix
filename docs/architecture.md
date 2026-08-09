# Architecture

## Role

`libpkgapply-posix` owns concrete POSIX mechanisms for the semantic application
engine in `libpkgapply`.

```text
libpkgapply request, plan, journal, and recovery authority
                         |
                         v
                 libpkgapply-posix
   descriptor-anchored observation, private staging, durable stores,
       target mutation leases, and concrete backend transactions
                         |
                         v
             caller-selected POSIX directories and target root
```

The repository does not decide what package operation is valid, construct an
operation plan, publish installed state, run lifecycle programs, or select host
paths. Those remain caller or semantic-owner responsibilities.

## Owned mechanisms

The library owns:

- FD-anchored target observation;
- caller-held target mutation leases;
- attempt-bound incoming payload staging;
- pre-mutation old-object capture;
- immutable rejected-object publication and direct record-identity reopening;
- atomic journal and restart-checkpoint stores;
- immutable completed-evidence publication;
- active namespace mutation and recovery; and
- composition of those mechanisms as `application_posix_backend`.

Every pathname-taking factory selects and opens authority once. Long-lived
objects retain duplicated descriptors so later pathname replacement cannot
redirect an admitted transaction.

## Non-ownership

The library does not own semantic identities received from `libpkgapply`,
`libpkgplan`, or `libpkgimage`. It validates bindings before acting but does not
redefine them. OpenSSL is a private provider used for hashing and nonce
material; no OpenSSL type appears in the installed API.

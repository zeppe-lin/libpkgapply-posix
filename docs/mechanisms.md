# POSIX mechanisms

These are the mechanisms owned by `libpkgapply-posix` 4.0.0. They are physical
providers, not alternate semantic authorities.

## Descriptor authority

Factories accept caller-selected paths or open directory descriptors and retain
descriptor authority. Final pathname components are not followed where a
symlink would redirect authority. Long-lived stores and transactions do not
re-resolve their original pathname after construction.

Regular retained records are opened nonblocking before `fstat`/type validation.
A FIFO, device, socket, or symlink substituted for a regular record therefore
fails closed instead of blocking restart.

## Journal store

`application_journal_store` implements the core
`pkgapply::application_journal_store` interface. It uses only the canonical core
transport codec for declaration, step, and cursor values.

The physical layout is exact-name indexed:

```text
JOURNAL-ROOT/
  journal-<declaration-id>/
    declaration.bin
    cursor.bin
    cursor.lock
    steps/
      00000000000000000000.bin
      00000000000000000001.bin
      ...
  active-request-<request-id>.ref
```

The names are mechanism indexes, not semantic truth. Loaded bytes are decoded by
`libpkgapply` and the resulting declaration/step identities and sequence are
checked against the exact address used to load them.

### Immutable declaration and steps

A candidate is written to a unique temporary regular file, synchronized, and
published to the exact final name with no replacement. The containing directory
is synchronized before success is returned. Exact canonical retry is accepted;
different bytes under an occupied immutable name fail as
`immutable_conflict`.

No directory enumeration participates in lookup or recovery.

### Bounded cursor

`cursor.bin` is mutable only through compare-and-publish. A per-journal advisory
write lock in `cursor.lock` serializes the read/compare/replace sequence across
processes. A candidate cursor is written and synchronized before atomic rename;
the journal directory is then synchronized.

A stale expected cursor fails as `cursor_conflict`. Exact retry of an already
visible desired cursor is accepted even when the caller's expected cursor is
old, covering uncertainty after rename but before directory synchronization
could be confirmed.

### Direct request locator

After a declaration is durable, the store atomically publishes a mutable
request-to-declaration reference. `load_active_declaration()` follows exactly
that file and validates that the referenced declaration exists and names the
requested application. It does not scan attempts or infer recency from directory
contents.

The locator is routing metadata only. Owner history is declaration + immutable
steps + cursor.

## Mutation backend

`application_posix_backend` retains only target, payload, capture, rejected, and
completed-evidence directories. It has no journal or checkpoint descriptor.
Calling transaction `synchronize(journal)` is rejected because journal
durability belongs to the separate store.

Fresh transactions perform observation, payload staging, old-object capture,
rejected publication, active mutation/recovery, mechanism durability, and
completed-evidence publication according to core-issued commands.

## Restart

The provider accepts an `application_restart_view` produced by `libpkgapply`
from owner history. It verifies the exact attempt identity and frozen request
bindings, then reopens subordinate evidence only where owner terminal facts say
a physical result completed:

- sealed incoming payloads are reopened from the payload store;
- completed captures are reopened and compared with retained observations and
  exact-recovery capability;
- completed rejected publication is reopened by exact request/record binding;
- completed evidence is reopened by its exact evidence identity;
- active/recovery state is reconstructed only as physical workspace authority
  needed by subsequent backend calls.

The provider does not append missing owner terminal events from physical
residue. An unresolved owner intent remains unresolved and core restart policy
decides recovery/replay safety.

## Completed evidence

Completed-evidence publication remains immutable and independently reopenable.
The provider validates request, attempt, target and physical store bindings; the
semantic engine owns journal/declaration and state-projection eligibility.

## Cleanup

Transaction destruction closes live descriptors and abandons incomplete private
construction. Durable journal steps, captures, rejected records, completed
evidence, and unresolved recovery workspace are not interpreted as garbage from
local filesystem state. Any future garbage collector must operate from explicit
owner/controller authority, not directory enumeration masquerading as history.

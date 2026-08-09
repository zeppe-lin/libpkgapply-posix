# POSIX mechanism protocols

The following mechanism notes were extracted from the libpkgapply 2.3.0 design document.
They describe the implementation owned by libpkgapply-posix 3.1.0.

The POSIX storage layer remains deliberately byte-oriented. Journal storage
derives one safe filename from the stable journal identity, opens the store as a
retained directory descriptor, writes a mode-0600 temporary regular file,
synchronizes the file, atomically renames it over the prior snapshot, and
synchronizes the directory. Failure after rename is reported separately as a
visible replacement whose directory durability is unconfirmed. Loads use
`openat()` without following the final symlink, require a bounded regular file,
decode the complete stream, and verify that filename and journal content name
the same journal. After one journal snapshot is durable, publication atomically
updates a separate request-identity index to that journal. The index is a direct
restart locator: it never scans the journal namespace or chooses among attempts.
A missing index means no attempt is admitted for restart; an index naming a
missing, corrupt, or foreign-request journal is contradictory storage authority.

Checkpoint storage derives a separate safe filename from the exact journal-
record identity. Each snapshot is immutable: publication writes and synchronizes
a mode-0600 temporary file, links it into the directory without replacement,
removes the temporary name, and synchronizes the directory. Exact republication
is accepted only when the existing bytes are identical; conflicting bytes under
the same journal-record identity are rejected. Loads verify the stored checksum,
exact journal binding, and typed request binding before returning replay facts.

The POSIX private payload namespace is also descriptor-anchored. A stage
directory is named by the full application-attempt identity rather than by a
package path, archive pathname, or nonce alone. Its immutable binding record
commits to the request-bound attempt, target, backend, nonce, package-image
identity, selected entry identifiers, canonical paths, declared sizes, and
regular-content identities.

Archive replay writes only selected regular entries. Pending files are private
mode-0600 records. `end()` verifies the exact declared size and SHA-256 content
identity, synchronizes the file, publishes its stable entry name, and
synchronizes the stage directory. A seal record is published only after every
selected entry completed. The seal record is identical to the binding record,
so restart lookup cannot reinterpret one stage under another image or
selection.

A retry under the same application attempt behaves according to physical
truth. An unsealed stage may be rewritten because it is private and has not
become replay authority. A sealed stage is never rewritten: archive replay is
compared byte-for-byte with the stored payloads and `seal()` returns the same
completed staging evidence. Loading a sealed stage rechecks the binding, file
type, size, stable descriptor interval, and content digest before granting a
read-only descriptor. Incomplete stages are not returned as restart authority.

This mechanism does not create active objects, rejected objects, recovery
captures, or journal facts. The complete backend composes it with the
semantic engine and retains its full application-attempt binding.

The POSIX old-object capture namespace is a separate attempt-bound authority.
Its directory name and immutable binding commit to the full application attempt,
not a package path or backend nonce. One capture record binds the exact logical
path, rejected/recovery purposes, admitted observation, and whether exact prior-
state restoration is physically supported.

Regular objects are copied from an `O_NOFOLLOW` descriptor during one stable
metadata interval. Bytes are streamed into a mode-0600 temporary file while size
and SHA-256 are checked against admission, then the file is synchronized and
linked into its immutable stable name. Non-regular captures retain the admitted
metadata after a before/after no-follow stability check. The immutable capture
record is synchronized and published only after any regular payload is visible.
A crash may therefore leave reusable private bytes, but never a record that
claims missing capture material.

Exact recovery requires known mode, ownership, and timestamp facts. Regular
objects additionally require known size and content identity. A multiply-linked
regular object is exact only when its admitted hard-link anchor resolves to the
same inode; an unknown relation remains usable as rejected bytes but cannot
claim exact topology restoration. Sockets and unclassified object kinds are not
captured as completed authority.

Capture reload verifies attempt, path, purpose, admitted observation, record
checksum, regular file type, size, stable descriptor interval, and content
identity before granting a read-only payload descriptor. Exact republication is
idempotent and does not reread a target that may already have changed. Namespace
synchronization remains a separate backend durability operation.

The POSIX rejected-object store is a separate attempt-scoped authority. Its
immutable binding commits to the application-attempt identity, request identity,
target identity, mutation-backend identity, nonce, and exactly one accepted
operation-plan identity. Separate `incoming-v1` and `old-v1` namespaces prevent
source-class aliasing. Every immutable record additionally binds the exact
rejected-effect request, logical path, source class, completed object facts,
completeness, and provenance.

Incoming publication first resolves the exact package-image entry named by the
rejected-effect request and verifies its logical path. Directories, symbolic
links, FIFOs, and device entries are published from those image facts without
inventing a payload-stage requirement. Regular and hard-link entries require a
sealed payload set bound to the same attempt, nonce, and package-image identity.
A direct regular entry remains a complete object fact with an unknown hard-link
relation: no peer anchor is asserted, but every state-publication-required object
fact comes from the sealed image. A hard-link record preserves its logical anchor
relation and copies the anchor's verified regular bytes, so restart does not
depend on private incoming staging or the current active target.

Old publication accepts only a capture from the same attempt and logical path
whose capture request explicitly admitted rejected-object use. Regular bytes are
copied from that immutable pre-mutation capture. The store never reopens the
managed-target path and therefore cannot substitute a post-mutation pathname for
old-object authority.

Regular payloads are size- and digest-verified, synchronized, and linked into
immutable stable names before their records are published. Record identities are
domain-separated over canonical source-bound record bodies. Exact republication
verifies the existing request, source, object facts, and payload before
returning the same record and backend-evidence identities. Restart loading
revalidates the
attempt and plan bindings, record checksum, request, source class, object facts,
and any regular payload before granting a read-only descriptor. Corrupt bindings
and records become typed rejected-store failures.

Non-regular objects remain typed records; the store does not materialize them as
live filesystem nodes. Record visibility does not claim rejected-store
durability. The backend must synchronize the attempt namespace separately and
report only the guarantee actually established. This mechanism neither mutates
the active namespace nor classifies the complete application outcome.

POSIX active namespace publication
----------------------------------

The active namespace is not another application controller. The complete POSIX
transaction binds the managed target root, application attempt, optional exact
package image, sealed payload authority, admitted observations, old-object
captures, journal, and outer lease once. Its `execute_active()` implementation
then receives only the exact command derived by the semantic engine.

A mechanism result has a strict visibility meaning. `completed` means the
requested effect is visible. `conditional_retained` is valid only when
`remove_directory_if_empty` proves a non-empty directory remained unchanged.
`failed` proves the logical target unchanged. Any syscall sequence that may
have changed the logical target but cannot prove the resulting state reports
`indeterminate`; the POSIX layer does not classify application success.

Incoming non-directory objects are prepared under an exclusive attempt-bound
name in the exact destination parent. Regular bytes are copied from the sealed
payload descriptor, verified, and assigned metadata before publication.
Symbolic links, FIFOs, and permitted device nodes are likewise complete before
their parent-local name is renamed onto the final leaf. The backend never opens
the final regular path with `O_TRUNC`, and a central staging filesystem is not
used as a substitute for same-filesystem publication.

A directory activated over an existing directory preserves that inode and
unmanaged children while applying only the planned directory metadata. A type
change involving a directory uses deterministic parent-local new and displaced
names; it never recursively deletes the directory. An incoming non-directory
may replace an existing directory only after that directory is proven empty.

An incoming hard link is created with `linkat()` from its exact logical anchor,
then verified as the same regular inode before publication. It is never copied
as an unrelated regular file. Because POSIX hard links share inode metadata,
the reference backend rejects an image binding whose hard-link mode, owner,
group, or timestamp differs from its regular anchor. `libpkgimage` should make
that impossible-image invariant canonical; until then the backend preflight
must refuse it before active mutation.

`remove_observed` is non-recursive. `remove_directory_if_empty` maps a proven
logically non-empty result to `conditional_retained`. A completed captured
descendant removal can leave an attempt-bound displaced-old name inside its
parent. That provider-owned recovery workspace is not application-visible
content: an ancestor directory may be displaced when every remaining entry is
the exact deterministic displaced name of an already-completed, captured
direct-child removal from the same attempt. Arbitrary hidden names, prefix
matches, unexpected object kinds, and unresolved directory reads remain
logical content or indeterminate authority; they are never ignored as recovery
workspace.

A completed child publication or removal can itself change metadata on an
admitted ancestor directory. Before reporting that child effect completed, the
POSIX mechanism re-establishes the selected admitted or incoming metadata for
affected ancestor directories and retains any changed directory descriptor for
active-namespace synchronization. It does not reinterpret provider-caused
metadata drift as fresh caller authority. Unexpected absence, type change,
ownership or mode change, or other race after admission is indeterminate unless
the mechanism can prove that its own command established the final state.

Recovery is selected and ordered by the core. The POSIX transaction restores
one path from deterministic workspace facts and the exact admitted prior-state
authority. Prior regular bytes come only from a verified capture, prior special
objects from exact captured facts, and prior absence is restored only by
removing an object proven to belong to the same attempt. Ambiguous workspace or
final-path state is indeterminate; incomplete capture authority never becomes a
claim of exact restoration.

Visibility and durability remain separate. Active publication records dirty
regular descriptors and affected parent directories. Synchronizing the active
namespace flushes the required content, metadata, and directory entries, and
clears no dirty state until the whole selected guarantee succeeds. A successful
`renameat()` is not promoted into global filesystem atomicity or durability.

The deterministic parent-local names are restart machinery, not canonical
application evidence. A reopened transaction inspects those names and the
logical leaf to distinguish an unexposed prepared object, a removed or replaced
object with displaced old authority, a visibly published incoming object, and
contradictory physical state. An unresolved journal intent is never blindly
issued a second time.

The reference implementation is a private, non-installed active-namespace
session rather than a second public executor. It binds image, payload,
observation, capture, target-root, and attempt authorities once. Existing
objects with recovery authority are displaced before replacement or removal,
preserving hard-link groups as physical old-object authority. When a captured
directory is removed after captured descendants, its displaced directory may
carry those exact descendant sidecars as one hierarchical recovery tree.
Reverse recovery restores the parent first and then consumes descendant
workspace through the restored logical path. A reopened transaction may retain
a completed descendant removal when an already-removed ancestor makes that
descendant path structurally absent.

Recovery consumes deterministic workspace truth first, then exact capture
material. Missing or contradictory authority reports `indeterminate`. After a
terminal application journal is durable, the complete transaction may discard a
hierarchical recovery tree only after recursively validating every entry as the
exact displaced name and object kind of an already-completed, captured removal
from that attempt. Unknown entries refuse cleanup before recursive deletion.
Once an ancestor recovery tree has been discarded, descendant cleanup is
idempotently covered by that ancestor. Unresolved workspace state is never
garbage-collected as though it were committed.

The session records completed in-process effect paths for recovery. Durable
restart reconstruction of that effect prefix remains the responsibility of the
complete POSIX backend transaction, which rebuilds the private session from
the validated journal and checkpoint before calling it. The mechanism alone
does not discover attempts, select journals, or classify terminal application
success.

POSIX completed-evidence storage
--------------------------------

Completed application evidence is a terminal application record, not a restart
checkpoint and not installed-state truth. The semantic engine constructs it only
after every selected effect, required synchronization, and final observation has
completed. The POSIX backend may publish only that exact validated value; it does
not rebuild evidence from journal progress, infer missing facts, or weaken the
completed-evidence eligibility rules.

The immutable record binds the completed-evidence identity and the full evidence
body: operation kind, request, plan, attempt, target, execution control, lease-
bound state projection, journal, normalized path consequences, six-domain
durability profile, and backend evidence. Its storage encoding is versioned,
bounded, checksummed, and independently revalidated against the immutable
application request before a reopened record is accepted. A journal identity or
checkpoint reference alone is never substituted for the evidence body.

Publication uses a private mode-0600 temporary regular file, synchronizes the
complete record before exposure, and installs an identity-keyed immutable name
without replacement. Exact republication is idempotent only when the existing
bytes decode to the same completed evidence. Conflicting, truncated, corrupt,
foreign-request, or identity-inconsistent records are typed failures and are
never treated as completed publication.

Visibility and durability remain separate. `publish_completed_evidence()` may
report `completed` after the immutable record is visible and returns exactly the
recorded completed-evidence identity. The later
`synchronize(completed_evidence)` operation flushes the record and namespace
metadata and reports only the durability it established. It does not upgrade
journal, checkpoint, active-namespace, rejected-store, or installed-state
durability.

The completed-evidence store is independent of the restart-checkpoint store.
Checkpoints retain resumable mechanism progress and may contain a copy of
completed evidence needed to continue terminal sealing. The completed-evidence
store publishes the terminal proof consumed by the caller and future state-side
adapter. Neither store acquires `libpkgstate` authority, and neither may publish
installed state.

On restart, a checkpoint that says evidence publication completed is accepted
only after the complete backend verifies the same immutable record. An unresolved
publication intent is not blindly repeated; the backend first distinguishes no
record, exact visible record, and contradictory storage state. Terminal cleanup
must not remove completed evidence while a receipt or durable journal still
references it.

POSIX backend transaction composition
-------------------------------------

The concrete POSIX backend is a mechanism composition root, not another
semantic engine. Its installed factory exposes the `application_backend`
contract required by the package manager. The concrete transaction remains
private to `libpkgapply-posix`; callers cannot invoke the journal, staging,
rejected, active, recovery, or evidence mechanisms out of core-derived order.

One backend instance is configured with retained descriptors and immutable
identities for the selected target root and every storage namespace. The
configuration must reproduce the target context's observation backend,
mutation backend, capability profile, root view, active namespace, rejected
store, staging namespace, journal namespace, and exclusion domain. A
transaction never discovers a root pathname, storage path, package archive,
plan, or lease from ambient configuration.

A fresh transaction borrows the caller's exact lease instance, duplicates the
configured descriptors, and issues one unpredictable attempt nonce. Beginning
a transaction performs no observation, journal publication, payload replay,
capture, rejected publication, active mutation, synchronization, or evidence
publication. Installation and upgrade bind the exact incoming package image;
removal binds no incoming-image authority and cannot later acquire one.

The transaction owns one coherent live view of the POSIX mechanisms:

```text
target observer
journal store              restart-checkpoint store
payload store              old-object capture store
rejected-object store      active-namespace session
completed-evidence store
```

The observer, capture store, and active session must remain anchored to the
same selected target-root object. All stores remain anchored to the namespace
descriptors fixed by backend configuration. Replacing a pathname used to open
a descriptor cannot redirect a live transaction to another target or store.

Each virtual operation delegates to exactly one mechanism and retains the
returned physical fact in transaction state. `synchronize(domain)` has an
explicit routing table for all six durability domains; it does not flush an
unrelated store or infer confirmation from an earlier rename, link, or journal
write. A synchronization syscall failure in an otherwise admitted domain is
returned as `unconfirmed` durability so the semantic engine retains the failed
persistence attempt in its receipt. Corruption, binding, and authority failures
remain mechanism exceptions rather than being laundered into durability facts.
Backend exceptions preserve whether publication or replacement may already be
visible so the core can classify other uncertainty truthfully.

`publish_journal()` is also the restart publication barrier. Before a journal
snapshot that depends on new mechanism facts becomes durable current truth,
the transaction constructs the exact checkpoint for that snapshot and
publishes it immutably. The checkpoint may become durable before the journal
snapshot; such an unreferenced checkpoint is harmless. The reverse order is
forbidden because it could expose a resumable journal without its exact replay
material. A journal snapshot and checkpoint are never updated in place as one
invented cross-file atomic object.

Reopening does not allocate a new attempt. The transaction derives the original
nonce from the supplied durable journal, reports that exact journal through
`resumed_journal()`, and loads only the checkpoint keyed by that journal-record
identity. It then verifies every checkpoint claim against the corresponding
physical authority: sealed payloads, captures, rejected records, active
workspace and final-path state, synchronization facts, and completed evidence
when present. Missing or contradictory authority is a restart failure or
indeterminate physical result, never permission to repeat an unresolved active
or recovery command.

The active session is rebuilt from the admitted observation closure, exact
captures, optional incoming image, sealed payloads, and durable forward and
recovery prefixes. Completed effects are registered as already attempted;
unresolved intents are represented as indeterminate and are not reissued.
Final observation may be repeated because it is read-only. Exact idempotent
private publication and synchronization may be retried only where the core
restart contract permits it.

Transaction destruction closes descriptors and abandons only unsealed private
construction. It does not delete durable checkpoints, captures, rejected
records, completed evidence, or unresolved active workspace. Displaced old
objects are discarded only after a terminal journal is durable and the core has
made recovery unnecessary. RAII cleanup never becomes transaction resolution.

The core does not enumerate durable attempts or select a journal. The caller
supplies one validated durable journal to `resume_application()`. The complete
backend reopens exactly that attempt and loads only the checkpoint keyed by the
supplied journal snapshot.

The installed implementation is
`application_posix_backend::from_directory_fds()`. Configuration duplicates the
already-selected target and store directory descriptors. Its public surface is
only the abstract backend contract; mechanism order and mutable transaction
state remain private to `libpkgapply-posix`.

## Caller-owned mutation lease

The POSIX provider consumes one already-selected lock-directory descriptor and
derives one coordination filename from the exact mutation-exclusion-domain
identity. The file is opened without following a final symlink and retained
under a nonblocking exclusive advisory lock. Acquisition creates no wait,
retry, or backoff policy. The immutable acquisition identity binds the exact
application target context, exclusion domain, and a mechanism-issued nonce.

The coordination file is never removed. Unlink or replacement invalidates the
live lease observation even though the old descriptor remains locked; this
prevents a caller from claiming exclusion after the named cooperative authority
has split. The lock directory is caller-selected configuration authority, not
a target discovered from pathnames or package state.

The lease establishes exclusion only among cooperating actors. Filesystem
operations still use stable root handles, no-follow component traversal, and
final observation because unrelated processes may ignore the protocol.


## FD-anchored target observation

`libpkgapply-posix` observes managed target objects relative to a retained root
directory descriptor. Parent components are opened one at a time with
`openat(2)`, `O_DIRECTORY`, and `O_NOFOLLOW`; a symbolic-link parent is an
observation error rather than an alternate route through the host namespace.
The leaf is inspected with no-follow metadata operations, so a leaf symbolic
link is reported as a symbolic link and is never traversed.

Regular content identities are SHA-256 digests of bytes read from an opened
regular-file descriptor. Metadata is sampled before and after the read. A
replacement or concurrent modification yields an unknown observation instead
of evidence assembled from different objects. Hard-link relations are claimed
only when the caller supplies an expected logical anchor and both paths are
observed as the same regular inode. The observer does not infer package
semantics from arbitrary inode aliases.

This layer is observation mechanism only. It does not acquire mutation leases,
execute active effects, capture recovery objects, or publish durable records.

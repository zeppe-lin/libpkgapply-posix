# POSIX mechanism qualification

The following qualification contract was extracted from the libpkgapply 2.3.0 test doctrine.

POSIX outer-lease tests
-----------------------

The caller-owned mutation-lease mechanism must prove:

* acquisition is anchored to an already-selected directory descriptor;
* one exclusion-domain identity maps to one deterministic coordination name;
* a competing holder is refused without waiting;
* the lock file is regular and is not removed on release;
* a final lock-file symlink is refused;
* unlink or replacement makes `held()` false;
* target context, exclusion domain, nonce, and acquisition identity remain exact;
* target-scope validation accepts another acquisition in the same target and
  exclusion domain without requiring or fabricating a state projection;
* target-scope validation rejects released, foreign-target, and foreign-domain
  leases;
* full validation accepts only a projection made under that exact acquisition;
  and
* acquisition and validation perform no installed-state read or target mutation.

POSIX backend tests
-------------------

The current journal and checkpoint stores run in unprivileged temporary
directories. Journal-store tests prove:

* stable directory-descriptor anchoring across pathname rename;
* refusal to open a final directory symlink;
* mode-0600 snapshot creation;
* exact encode, publish, load, and identity preservation;
* atomic monotonic replacement and exact idempotent republication;
* stale snapshot rejection;
* corrupt byte-stream rejection; and
* absence of leftover temporary files after successful publication.

Checkpoint codec and store tests prove:

* exact binding to one journal-record identity and immutable typed request;
* byte-stable round trips including completed application evidence;
* rejection of truncation, same-length checksum corruption, and foreign plans;
* immutable link-without-replace publication and exact republication;
* conflict rejection for different checkpoint bytes under one journal record;
* mode-0600 regular files and descriptor anchoring across directory rename; and
* corrupt stored-byte rejection before replay.

Private payload-stage tests prove:

* one full application-attempt identity owns one stage directory;
* image and exact regular-entry selection are fixed before replay;
* zero-length and non-empty regular payloads are accepted;
* size and SHA-256 content mismatches are rejected before sealing;
* sealed replay verifies bytes without rewriting the stage;
* another selection cannot reuse the same application attempt;
* abandoned or incomplete stages are not restart authority;
* sealed descriptors remain available after namespace pathname movement; and
* stored-file corruption is rejected before a read descriptor is granted.

Private old-object capture tests prove:

* the full application-attempt identity owns each capture namespace;
* path and rejected/recovery purposes are immutable bindings;
* regular bytes survive subsequent target replacement;
* a fresh attempt refuses a source that differs from admission;
* multiply-linked regular objects do not claim exact recovery without a proven
  anchor;
* a proven hard-link relation retains exact-recovery authority;
* symbolic links and FIFOs retain exact admitted object facts;
* idempotent capture replay does not reread the changed target;
* foreign attempts cannot alias existing capture material; and
* storage and target descriptors remain authoritative after pathname movement.

Immutable rejected-store tests prove:

* one full application-attempt identity owns each rejected namespace;
* one accepted operation-plan identity binds the complete attempt namespace,
  including previously unpublished paths;
* incoming and old records cannot substitute for one another;
* metadata-only incoming packages require no fabricated payload stage;
* incoming regular and hard-link records refuse publication without the exact
  sealed attempt, image, and payload authority;
* failed source-authority checks leave no completed rejected record;
* old records consume only pre-mutation captures admitted for rejected use;
* direct regular records remain complete without inventing a hard-link peer,
  while hard-link records retain the exact admitted anchor relation;
* regular and hard-link records retain independently verified, self-contained
  bytes;
* hard-link records preserve their logical anchor relation;
* directories, symbolic links, FIFOs, and devices retain typed facts without
  granting regular-payload descriptors or creating live special objects;
* exact republication returns the same immutable record identity;
* completed record identity directly reopens incoming, old, regular, and
  non-regular self-contained evidence without a planner command;
* missing direct selectors grant no authority and exact republication repairs
  an interrupted identity-index publication;
* direct identity reopening validates the record identity and payload bytes,
  while remaining independent of the attempt binding used by restart;
* foreign attempts, foreign plans, and source mismatches are rejected;
* restart loading rejects malformed bindings, malformed records, and corrupted
  payloads through typed store failures before granting a descriptor;
* namespace descriptors and direct identity lookup remain authoritative after
  pathname movement; and
* record visibility and namespace synchronization remain separate operations.

Active-namespace qualification is split by mechanism boundary. Workspace tests
must prove:

* deterministic attempt- and path-bound names in the exact destination parent;
* exclusive no-follow creation and collision refusal before target mutation;
* descriptor anchoring across target-root and parent pathname movement;
* no traversal through a symbolic-link parent;
* no central-filesystem assumption for publication; and
* conservative classification of fresh and unresolved workspace states.

Incoming-publication tests must prove:

* regular and zero-length bytes come only from the exact sealed payload entry;
* the final regular pathname never exposes a partially copied payload;
* directory, symbolic-link, FIFO, and capability-gated device publication;
* preservation of existing directory contents during metadata activation;
* non-recursive empty-directory type replacement;
* hard links share the exact active or retained regular anchor inode;
* contradictory hard-link inode metadata is refused before active mutation;
* parent-local temporary collisions leave the logical target unchanged; and
* any uncertainty after a potentially visible mutation is indeterminate.

Removal and recovery tests must prove:

* `remove_observed` never performs recursive deletion;
* only `remove_directory_if_empty` may return `conditional_retained`;
* a logically non-empty cleanup directory remains unchanged, while exact
  same-attempt recovery sidecars do not turn an otherwise empty owned directory
  into `conditional_retained`;
* arbitrary workspace-like names and wrong-kind sidecars are never ignored as
  provider-owned recovery authority;
* descendant mutation does not stale admitted ancestor-directory authority,
  including after active-session rebind and terminal workspace cleanup;
* nested captured removal can survive rebind, recover parent-to-child from the
  hierarchical displaced tree, and retain exact descendant bytes;
* terminal cleanup recursively deletes only a fully validated attempt-owned
  recovery tree, refuses an injected foreign entry before recursive deletion,
  and treats later descendant cleanup as already covered;
* prior absence, regular, directory, symbolic-link, FIFO, and supported device
  states are restored only from exact attempt-bound authority;
* reverse recovery does not recreate a hard link as unrelated bytes;
* incomplete capture authority cannot claim exact restoration;
* contradictory final or workspace facts become indeterminate; and
* active visibility remains separate from namespace synchronization.

The POSIX mechanism suite directly exercises parent-local publication,
preserved old leaves, regular and directory recovery, non-recursive removal,
hard-link recovery without byte-copy degradation, prior-absence restoration,
missing-capture indeterminacy, terminal displaced-old cleanup, and independent
namespace synchronization. Complete-backend tests separately exercise exact
factory identities, no-effect construction, nonce uniqueness, descriptor
anchoring, checkpoint-before-journal publication, durable attempt reopening,
physical restart revalidation, and terminal evidence.

Completed-evidence store tests must prove:

* only a validated `completed_application_evidence` value is accepted;
* installation, upgrade, and removal evidence round-trip against their exact
  immutable request;
* the stored body retains every identity, path consequence, durability fact,
  and backend-evidence identity;
* publication uses a mode-0600 regular file and exposes no partial record;
* an exact republication returns the same completed-evidence identity;
* historical and restart-rebound completed-evidence identities can coexist
  without either immutable record replacing the other;
* a different record cannot replace an existing identity-keyed record;
* truncated, same-length corrupted, checksum-invalid, foreign-request, and
  identity-inconsistent records are rejected before publication is claimed;
* record visibility and completed-evidence synchronization remain separate;
* descriptor anchoring survives store pathname movement;
* restart verifies an already-published record before skipping publication; and
* checkpoint, journal, rejected-store, active-namespace, and installed-state
  durability are not implied by completed-evidence synchronization.

Complete POSIX transaction-composition tests must prove:

* configured backend identities exactly match the supplied target context;
* a fresh transaction borrows one held lease and issues one attempt nonce;
* construction performs no observation, journal, staging, or mutation action;
* installation and upgrade retain the exact incoming image while removal can
  never obtain incoming-image authority;
* observer, capture, and active mechanisms share the selected target-root
  object and remain descriptor-anchored after pathname replacement;
* each backend operation delegates once to the correct mechanism and retains
  the exact physical result and evidence identities;
* every durability domain routes only to its owning synchronization mechanism;
* a checkpoint containing new facts is durable before the journal snapshot
  that first references those facts;
* failure between checkpoint and journal publication leaves no resumable
  journal without replay material;
* restart reproduces the original attempt nonce and exact journal identity;
* every checkpoint claim is revalidated against sealed payload, capture,
  rejected, active-workspace, and completed-evidence authority;
* a checkpoint retaining historical completed evidence can be reopened under a
  new lease, publish current-projection evidence, reconfirm its durability, and
  advance a later checkpoint to that rebound evidence without mutating the
  historical record;
* completed prefixes are skipped, unresolved active or recovery intents are
  never reissued, and unstarted work remains in frozen schedule order;
* transaction destruction preserves durable and unresolved recovery authority;
  and
* terminal cleanup occurs only after the durable journal makes recovery
  unnecessary.

The unprivileged composition corpus drives the concrete backend through regular
payload installation, metadata-only installation, incoming rejected staging,
old-object capture and rejected staging, active removal, six-domain durability,
and completed-evidence publication. It also rejects invalid descriptors,
foreign targets, wrong transaction forms, foreign images, released leases, and
restart journals without checkpoints.

The complete reference backend must additionally qualify:

* path replacement races where controllable;
* outer-lock interoperability with another process;
* rejected-store collision prevention;
* synchronization failure; and
* unchanged out-of-scope paths.

Device-node behavior uses capability-gated integration tests. The scripted
backend qualifies semantic behavior where the test environment lacks
privilege.


## POSIX target observation

The POSIX observer tests use a temporary target tree to verify descriptor-anchored
regular-file hashing, metadata capture, symbolic-link inspection, FIFO and
absence classification, explicit hard-link proof, root-pathname replacement,
and refusal to traverse a symbolic-link parent. The observer is read-only; no
mutation backend authority is exercised by these tests.

# Testing libpkgapply-posix

Qualification is organized by authority role:

```text
tests/
├── contracts/
├── fixtures/
├── header/
├── integration/
├── mechanism/
└── unit/
```

Meson suites are `unit`, `mechanism`, `integration`, `header`, and `contract`.

1. `unit` qualifies typed POSIX error values and stable mechanism vocabulary.
2. `mechanism` attacks individual physical providers: descriptor anchoring,
   no-follow/nonblocking regular-file admission, immutable publication,
   corruption refusal, exact reopening, synchronization failures, recovery,
   bounded descriptor cardinality, and `RLIMIT_NOFILE` pressure.
3. The journal-store mechanism additionally proves declaration/step/cursor
   persistence, immutable sequence conflict refusal, stale cursor CAS refusal,
   exact idempotent cursor retry, direct request lookup, orphan-step retention,
   descriptor anchoring after pathname replacement, FIFO corruption refusal,
   and exact stored-byte accounting. The accounting deliberately excludes no
   hidden snapshot or checkpoint: the journal namespace may contain only one
   declaration, immutable steps, one bounded cursor, and the zero-byte cursor
   lock needed for cross-process CAS serialization.
4. `integration` composes the public POSIX backend with real `libpkgapply`
   authority and a separate POSIX journal store. It covers complete routing,
   descriptor retention, completed evidence, durability failures, and an
   interrupted owner-journal restart through `resume_application()` rather than
   manufacturing a provider replay aggregate.
5. `header` compiles each installed header independently.
6. `contract` proves repository separation, dependency placement, exact ABI and
   RTTI surface, pkg-config metadata, documentation, release metadata, and the
   test topology itself.

White-box active-namespace/workspace tests link a private static target built
from the production source list. Private detail symbols are not promoted into
the shared ABI.

Shared product qualification requires provider SONAME 3 and semantic-core
`NEEDED libpkgapply.so.4`. Public pkg-config requirements include
`libpkgapply >= 4.0.0, < 5.0.0` and `libpkgimage >= 0.4.0`; direct planner and
crypto edges remain private.

Sanitizer jobs build the complete dependency chain with ASan and UBSan. The
documentation parser receives the complete public include closure explicitly so
qualification cannot borrow zoo headers from an ambient prefix.

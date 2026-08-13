# Testing libpkgapply-posix

Qualification is organized by evidence ownership rather than by implementation
filename:

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
The always-registered surface contains one unit executable, direct mechanism
executables, composed integration executables, and standalone public-header
compilations. Source, manual, repository, and ABI contracts are registered by
role; shared builds additionally qualify the reviewed ELF ABI surface.

The evidence roles are distinct:

1. `unit` qualifies local typed values and stable error vocabularies without
   requiring a filesystem mechanism.
2. `mechanism` exercises descriptor anchoring, refusal categories, immutable
   publication, exact replay, synchronization, recovery, and crash seams. Tests
   of the non-installed active-namespace and workspace implementation link a
   private static test target built from the production source list; they never
   require private symbols from the installed shared library.
3. `integration` composes the public POSIX backend with real `libpkgapply`
   authority. It covers factory/request binding, complete mechanism routing,
   restart, descriptor retention, completed rejected-record identity reopening,
   historical-to-current completed-evidence projection refresh, and all six
   durability domains. The
   durability-failure case injects real `fsync(2)` failure: active-namespace
   fault classification is proved at the direct mechanism seam, while journal,
   incoming staging, recovery staging, rejected storage, and completed evidence
   are proved through `application_backend_transaction::synchronize()`.
4. `header` compiles every installed header independently through one generic
   consumer translation unit. No umbrella include is allowed to mask a missing
   public dependency.
5. `contract` proves repository separation, extraction provenance, dependency
   placement, ABI/RTTI surface, pkg-config metadata, documentation, style,
   release metadata, and the test-role topology itself.

Installed shared and static consumers use only pkg-config output. Shared-library
audits verify provider SONAME 2, semantic-core NEEDED entry
`libpkgapply.so.3`, direct dependency closure, exact callable and RTTI/vtable
exports, symbol versioning, and absence of non-`pkgapply::posix` C++ exports.

Sanitizer jobs build the complete dependency chain with ASan and UBSan. Tests
which require Linux/POSIX filesystem semantics run only on a compatible host;
they do not silently downgrade to model-only assertions.

The documentation contract parses public headers against the complete transitive
public include closure resolved by Meson:

```text
libpkgapply
libpkgbuild-plan
libpkgplan
libpkgbuild-image
libpkgbuild
libpkgimage
libpkgsource-plan
libpkgsource
libpkgresolve
libpkgcatalog
libpkgstate
```

Every dependency is passed as an explicit include root. Qualification therefore
does not borrow transitive zoo headers from one ambient installation prefix.

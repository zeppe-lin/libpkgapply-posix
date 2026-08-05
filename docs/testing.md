# Testing contract

Qualification covers five layers.

1. Every installed header compiles independently and through the umbrella.
2. Mechanism tests exercise descriptor anchoring, refusal categories,
   immutable publication, exact replay, synchronization, and crash seams.
   Tests of the non-installed active-namespace and workspace implementation
   link a private static test target built from the production source list;
   they never require private symbols from the installed shared library.
3. Source contracts prove repository separation, extraction provenance,
   dependency placement, export annotations, documentation, and release
   metadata.
4. Installed shared and static consumers use only pkg-config output.
5. Shared-library audits verify SONAME 2, direct dependency closure, exact
   callable and RTTI/vtable exports, symbol versioning, and absence of
   non-`pkgapply::posix` C++ exports.

Sanitizer jobs build the complete dependency chain with ASan and UBSan. Tests
which require Linux/POSIX filesystem semantics run only on a compatible host;
they do not silently downgrade to model-only assertions.

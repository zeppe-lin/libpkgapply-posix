# Extraction from libpkgapply 2.3.0

`libpkgapply` 2.3.0 shipped `libpkgapply-posix.so.2`, its installed headers,
manual, and tests from the semantic core repository. The 3.0 line separates
that existing product without rewriting mechanism bodies.

The root commit of this repository preserves the extracted implementation,
public declarations, focused tests, and manual. The extraction contract compares
that root material with recorded source hashes. Later commits may evolve the
independent product; provenance is not a permanent ban on legitimate fixes.

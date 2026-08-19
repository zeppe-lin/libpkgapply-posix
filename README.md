# libpkgapply-posix

`libpkgapply-posix` is the concrete POSIX mechanism provider for
`libpkgapply`.

It implements descriptor-anchored target observation, caller-owned mutation
leases, private payload staging, old-object capture, rejected-object storage,
completed-evidence publication, active namespace mutation/recovery, and a
separate exact-name POSIX store for the owner-authored append-only application
journal.

The journal store persists only canonical `libpkgapply` declaration, immutable
step, and bounded cursor bytes. It does not encode semantic journal values,
reconstruct execution history, enumerate storage to discover truth, or own a
restart checkpoint.

Regular-file authority is opened nonblocking before type validation, so FIFO or
other special-file corruption fails closed instead of wedging restart or
evidence reopening.

The library does not construct package plans, decide application policy,
publish installed state, execute lifecycle programs, discover storage paths, or
own package-manager configuration. Callers select target and storage authorities
explicitly and wire the mutation backend and journal store as separate objects.

## Why this is separate

`libpkgapply` owns requests, semantic history, replay interpretation, recovery
selection, and canonical journal transport encoding. POSIX mechanisms own
filesystem system calls, descriptor lifetime rules, durable byte publication,
and platform-specific failure modes. Another backend can satisfy the same
semantic contract without inheriting this storage layout.

## Products

- `libpkgapply-posix.so.3` — generation-3 POSIX mechanism ABI for
  `libpkgapply` generation 4.
- `libpkgapply-posix.3` — installed API and operational contract.

## Build

```sh
meson setup build \
  -Ddefault_library=shared \
  -Dlink_mode=shared \
  -Dwerror=true
meson compile -C build
meson test -C build --print-errorlogs
```

Build shared and static closures separately. See `DESIGN.md`,
`docs/integration.md`, `TESTING.md`, and `docs/abi.md` before changing a
boundary.

## License

GPL-3.0-or-later. See `COPYING` and `COPYRIGHT`.

# libpkgapply-posix

`libpkgapply-posix` is the concrete POSIX mechanism provider for
`libpkgapply`.

It implements descriptor-anchored target observation, caller-owned mutation
leases, private payload staging, old-object capture, rejected-object storage and direct identity reopening,
durable journals and restart checkpoints, completed-evidence publication,
active namespace mutation and recovery, and the composed
`application_posix_backend`.
Regular-file authority is opened nonblocking before type validation, so FIFO or
other special-file corruption fails closed instead of wedging restart or evidence
reopening.

The library does not construct package plans, decide semantic application
policy, publish installed state, execute lifecycle programs, discover storage
paths, or own package-manager configuration. Callers select all target and
storage authorities explicitly.

## Why this is separate

`libpkgapply` defines semantic requests, evidence, recovery obligations, and
abstract backend contracts. POSIX mechanisms add filesystem system calls,
descriptor lifetime rules, private storage protocols, and platform-specific
failure modes. Keeping those bodies separate allows another backend to satisfy
the same semantic contract and prevents host mechanics from contaminating the
core ABI.

## Products

- `libpkgapply-posix.so.2` — POSIX mechanism implementations and backend
  composition.
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

Build shared and static closures separately. See `docs/architecture.md`,
`docs/integration.md`, `docs/testing.md`, and `docs/abi.md` before changing a
boundary.

## License

GPL-3.0-or-later. See `COPYING` and `COPYRIGHT`.

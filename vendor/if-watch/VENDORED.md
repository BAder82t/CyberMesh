# Vendored: if-watch 3.2.2 on the netlink 0.9 crates

This directory is a copy of [`libp2p/if-watch`](https://github.com/libp2p/if-watch) at tag `v3.2.2`
(commit `f6271229b3505bb1e245aad3d078bf571bb4e20e`), used through `[patch.crates-io]` in the
repository's root `Cargo.toml`. It is not a CyberMesh crate and is not a workspace member.

## The one change

`Cargo.toml` only: the Linux netlink dependencies move to their 0.9 line.

| Crate | 3.2.2 | here |
|---|---|---|
| `netlink-sys` | 0.8.8 | 0.9.0 |
| `netlink-packet-core` | 0.8.1 | 0.9.0 |
| `netlink-packet-route` | 0.28.0 | 0.33.0 |
| `netlink-proto` | 0.12.0 | 0.13.0 |
| `rtnetlink` | 0.20.0 | 0.23.0 |

These are the same five lines as `libp2p/if-watch` pull request #55 (open since 2026-08-31, not yet
reviewed or released). Every other file is byte-for-byte upstream v3.2.2, apart from this note.

## Why

`netlink-packet-core` 0.8.x depends on `paste` (RUSTSEC-2024-0436, unmaintained), a compile-time
macro that is in the Linux build only. `netlink-packet-core` 0.9.0 does not. `if-watch` is the only
thing in the dependency tree that still asks for 0.8.x, and it has not released since March 2026.

## Tested

On Linux x86_64 (2026-11-22 and 2026-11-23), with this vendored copy:

- the CyberMesh workspace passes `cargo check --all-targets --locked`, `paste` matches no package in
  the Linux graph and `netlink-packet-core` is 0.9.0;
- the `cybermesh-network` tests pass (11, real libp2p over TCP);
- `if-watch`'s own 4 tests pass (`cargo test --features tokio,smol` in this directory: they need both
  runtimes, and with only `tokio` the test module does not compile; its source is identical to
  upstream's, so that is upstream's test setup, not this change). Two of them
  watch the real network interfaces through the netlink 0.9 crates.

This directory is outside the workspace, so `cargo test --workspace` does not run those 4 tests.

## Licence

`if-watch` declares `MIT OR Apache-2.0` in its `Cargo.toml` (kept unchanged). The upstream repository
ships no licence files, so none are included here. Authors named in `Cargo.toml`: David Craven and
Parity Technologies Limited.

## When to remove it

When `libp2p/if-watch` releases a version on the netlink 0.9 line (or newer): delete this directory,
the `exclude` entry and the `[patch.crates-io]` entry in the root `Cargo.toml`, then run
`cargo update -p if-watch`. `cargo tree -i paste --workspace --target all` should find nothing.
Do not edit the vendored files meanwhile, so the diff against upstream stays these five lines.

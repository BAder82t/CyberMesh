# Trust Fabric: entropy model

Status: experimental, unaudited. Implemented in `crates/cybermesh-entropy`.

Information-theoretic protocols spend secret material that two parties provisioned ahead of
time. Spending any of it twice voids the guarantee, so the crate's job is "each byte at most
once, across crashes and restarts".

## Kinds of randomness

| Provenance | Meaning | Accepted |
|---|---|---|
| `ProvisionedShared` | secret bytes provisioned to both parties out of band | yes |
| `QuantumShared` | shared secret key from a QKD system | yes |
| `LocalSecret` | uniform secret bytes only this party has | yes, never as a shared pad |
| `Pseudorandom` | deterministic expansion of a short seed | refused |
| `Public` | known to others | refused |

The crate cannot verify provenance: it records the operator's declaration and refuses the
declarations that cannot support an information-theoretic claim. Locally generated randomness
does not become shared secret randomness between remote parties by being stored in a pool.
Encryption and authentication material live in separate pools (`Purpose`), and a reservation
says which, so a MAC layer can refuse pad bytes.

## Spending a byte

1. Take an exclusive file lock (cross-process) and a mutex (threads).
2. Advance the cursor past the region and **sync it first** (write-ahead).
3. Read the region, overwrite it with zeros, sync.
4. Return a `Reservation`: owns the bytes, zeroized on drop, not `Clone`, redacted `Debug`.

| Event | Result |
|---|---|
| crash after step 2 | the region is burned, never reissued (tested) |
| torn cursor write | the cursor has two alternating checksummed slots; the older one survives |
| old cursor restored | the regions it names are erased: `Burned`, fail closed (tested) |
| both cursor slots damaged, cursor beyond the pool, wrong pool id | refuse to open |
| pool exhausted | `Exhausted`, nothing spent; `needs_replenishment(low_water)` says when to top up |
| two handles or processes | serialised by the file lock; a test shows duplicates appear without it |

Files are created `0600`; opening a group- or world-accessible pool is refused.

## What it does not do

* A restore of the whole pool directory from a backup brings the erased material back and cannot
  be detected locally. With a live, honest peer the transport detects a one-sided restore and
  burns past it, but a restore of both parties goes unnoticed (tested; `known-issues.md` #1).
  Defence: no backups of pool directories, or an external monotonic counter.
* It manages one party's copy. Peers must consume matching offsets in the same order and append
  the same replenishment; nothing here synchronises them.
* Erasure is a file overwrite. Journaling file systems, snapshots and flash wear levelling can
  keep old copies. Pools are not encrypted at rest.
* Reservations are 8 bytes to 16 MiB. The 8-byte minimum is what makes "erased region" a
  reliable signal (an all-zero 8-byte region has probability 2^-64 by chance).
* Entropy accounting counts bytes, not an entropy estimate of their source.
* Needs Rust 1.89 (`File::lock`).

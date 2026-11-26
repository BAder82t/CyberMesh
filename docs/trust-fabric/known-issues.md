# Trust Fabric: known issues register

Status: experimental, unaudited. The first two issues are **Critical**: until they are closed,
nothing in the Trust Fabric should protect real traffic, and none of it has been tagged or
released. Severity and status in the first three columns are the reviewer's classification; the
other columns say what the repository does today and what would close the item.

| # | Issue | Severity | Status | What exists now | What would close it |
|---|---|---|---|---|---|
| 1 | Complete entropy-pool backup restoration can resurrect consumed secrets | Critical | Unresolved | See below | An external monotonic counter or witness that survives the pool being restored, or a policy and tooling that make restores impossible |
| 2 | Secret-resource synchronisation between peers | Critical | Unresolved | See below | Authenticated, multiplexed agreement on pool offsets, with a defined recovery when parties disagree |
| 3 | Information-theoretic authenticated handshake | Critical | Not demonstrated | A MAC-based handshake with transcript binding (`transport-protocol.md`) | A composable security statement and proof for the whole protocol, and a machine-checked model |
| 4 | Independent verification of entropy provenance | High | Operator-declared | `Provenance` is a label the operator sets; pools refuse pseudorandom and public declarations | Nothing in software can verify it: needs an out-of-band provisioning ceremony and attestation |
| 5 | Secure erasure on SSDs and snapshot-based storage | High | Best effort | Consumed regions are overwritten with zeros and synced | Storage that guarantees erasure (or encrypted-at-rest pools with key destruction) and snapshot discipline |
| 6 | Distributed identity and authentication | High | Pairwise MAC only | Pairwise MACs; an in-memory registry and policy (`trust-policy.md`) | A way to bind identities to pairwise material across many parties and agree on membership |
| 7 | Side-channel resistance | High | Not independently verified | Field multiplication without secret-dependent branches or tables; constant-time tag compare | An independent timing and side-channel review, and constant-time elimination and decoding |
| 8 | Publicly verifiable unconditional authentication | Research | Not provided | Symmetric MACs only: the receiver could forge | Unconditionally secure signature schemes need per-user signing and verification and explicit dispute-resolution trust assumptions (Swanson and Stinson); not implemented |

## 1. Backup restoration

A complete copy of a pool directory brings back the cursor **and** the unerased material.
Tested (`cybermesh-transport`, `resync/tests.rs`):

* **The risk is real.** After a full restore the pool offers the pad bytes that were already used
  (`a_restored_pool_hands_out_pad_bytes_that_were_already_used`).
* **One party restored, peer live and honest: detected and healed.** The peer's copy is ahead, so
  the next handshake fails with `OutOfStep` before consuming anything; resync burns the restored
  side forward to the peer's cursor, erasing the material below it, and later traffic uses
  fresh bytes (`restoring_one_party_is_detected_by_the_live_peer_and_healed_without_reuse`).
  This depends on the restored party running the handshake before sending anything, which the
  session API forces, and on the peer being honest and not itself restored.
* **Both parties restored to the same moment: not detected.** Their cursors agree, the
  handshake succeeds, and the same plaintext meets the same pad, giving the same ciphertext
  (`restoring_both_parties_is_not_detected_and_reuses_the_pad`). With two different plaintexts
  under that pad, the XOR of the ciphertexts is the XOR of the plaintexts.
* **Not covered:** a peer that is gone, or that lies about its cursor, or an attacker who
  restores one side and blocks the peer. Nothing local can distinguish a restore from the
  original state, which is why this stays Critical.

Operational rule until it is closed: **no backups of pool directories**, and treat any restore
or disk image rollback as a full compromise of the affected pools.

## 2. Synchronisation between peers

Partially mitigated, not resolved. Built: the handshake compares pool cursors before consuming
anything (`OutOfStep`); `resync` burns both sides forward to the larger cursor (it cannot move
backwards), bounded by pool size and a caller policy. Not built or open:

* **The sync message is unauthenticated.** That is safe for secrecy (burning only wastes
  material) but a forger can make a party burn material up to the policy limit: denial of
  service.
* **Resync is manual and needs a quiescent pair.** No automatic recovery, no detection of when
  to run it.
* **No multiplexing.** Concurrent sessions over the same pools are not supported; an
  ordering-aware allocation across sessions is not designed.
* **No agreement on what was lost.** A crash that loses sent-but-undelivered records is healed
  by burning, so material is spent without carrying data.
* A peer that is wrong or malicious about its cursor is not distinguished from one that merely
  crashed.

## 3. The handshake

The protocol (hello, hello, finished, with the MAC covering both hellos) has unit,
mutation and property tests, and its limits are written down. It has **no formal model, no
composable security proof, no analysis of the whole protocol against an active adversary, and
no independent review**. Until it does, "information-theoretically secure handshake" is a design
intention, not a result.

## 4 to 8

* **4. Provenance.** A pool created with `ProvisionedShared` is only as good as the operator's
  claim about how the bytes were made and delivered. The crate refuses `Pseudorandom` and
  `Public` declarations; it cannot tell a good source from a bad one.
* **5. Erasure.** `Pool` overwrites consumed regions and syncs. Journaling file systems,
  snapshots, flash wear levelling and backups can keep old copies. Pools are not encrypted at
  rest.
* **6. Identity.** Approvals and shares are authenticated with pairwise MACs; there is no group
  identity, no public key infrastructure (by design: it would be computational), and the
  registry is in-memory, without persistence, rollback protection or agreement across
  verifiers.
* **7. Side channels.** Field multiplication and tag comparison avoid secret-dependent
  branches and table lookups. Reed-Solomon elimination, Lagrange interpolation, share
  validation and the pool's file I/O are not constant time, and nothing has been reviewed or
  measured.
* **8. Public verifiability.** Every tag is symmetric: the holder of the key can both make and
  check it, so tags convince only their verifier and give no non-repudiation. Governance and
  identity signatures elsewhere in CyberMesh stay Ed25519 and are computational.

## Literature behind the register

`literature-review.md` records what the sources say. For #1 the known direction is a protected
monotonic counter or a quorum of witnesses (ROTE, Ariadne and Memoir address rollback for trusted
execution; none applies to a pool of plain files without protected hardware). For #4, NIST SP
800-90B says its estimation methods rest on statistical assumptions and "should not replace
in-depth analysis" of the noise source. For #5, Wei et al. found that overwriting the whole visible
address space twice is usually, not always, sufficient on SSDs and that file-level techniques
designed for hard drives are not effective; Gutmann 1996 covers magnetic media and volatile memory,
**not flash**, and NIST SP 800-88 Rev. 1 was withdrawn on 2025-09-26 in favour of Rev. 2. For #8,
Swanson and Stinson. For #7, Kocher 1996 and Bernstein 2005.

## What this register does not cover

This is the list the review raised. The limits of each crate are in `limitations.md`,
`authentication.md`, `transport-protocol.md`, `trust-policy.md`, `secure-routing.md` and
`private-computation.md`. A first verified literature review is in `literature-review.md` (73 records; read its section 1 for what
the verification levels do and do not show). The formal models and the paper have not been written, and no
benchmarks of the real protocol code exist yet (`simulation.md` covers the routing and budget model only).

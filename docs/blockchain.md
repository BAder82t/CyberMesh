# Anchoring and the role of blockchains

## 1. What problem anchoring solves (and what it does not)

Signatures already prove *who* published a release. Two weaknesses remain:

1. **Split view and rewriting history.** A threshold of release signers could show different users different releases with the same sequence number. They could also later deny having published a release.
2. **Time.** A signature does not prove *when* the signing happened.

An append-only transparency log of release digests addresses (1): consistency proofs show the history was only ever extended, and an inclusion proof shows that a specific release is part of it. Anchoring the log's checkpoint with an independent third party adds (2), and gives evidence of (1) that the log operators cannot rewrite on their own.

Anchoring does **not** affect real-time protection. Consumers check signatures only, so phishing protection keeps working through a chain or calendar outage, or with no anchor at all.

## 2. Design

```mermaid
flowchart LR
  R1[release seq 1 digest] --> L
  R2[release seq 2 digest] --> L
  R3[release seq 3 digest] --> L
  L[(RFC 9162 Merkle log<br/>leaves = {sequence, digest})] --> CP[checkpoint<br/>size + root]
  CP --> CM["commitment = H(log_id, size, root)<br/>(32 bytes)"]
  CM --> A1[Local test chain]
  CM -.optional.-> A2[OpenTimestamps → Bitcoin]
```

- **Merkle log.** The log uses RFC 9162 hashing (`0x00` leaf prefix, `0x01` node prefix). It supports inclusion and consistency proofs, verified with the RFC's algorithms. Exhaustive tests cover trees of 1–33 leaves, and property tests cover sizes up to 200.
- **Commitment.** Only a single 32-byte domain-separated hash ever leaves the log. No URLs, domains, organisation names or infrastructure identifiers are anchored.
- **`Anchor` trait.** `submit(commitment) -> AnchorReceipt`. Receipts are verified offline per adapter.
- **Failure isolation.** An adapter error (`Unavailable`, `Timeout`, a corrupt receipt) is reported and the operator can retry. `cybermesh anchor commit` exits with code 3, and release publication is unaffected. Failure modes are tested with `FailingAnchor`.

### 2.1 Local test chain (`LocalChain`)
This is a hash-linked, append-only block file. It reproduces the *verification* workflow of a public chain:
- receipts contain the block;
- verifiers recompute the block hash;
- verifiers optionally check the block against a validated copy of the chain, as a light client would.

It provides no decentralisation and no third-party witness. It exists for tests and the demo.

### 2.2 OpenTimestamps adapter (feature `ots`)
- **Submission.** The client sends `SHA-256(commitment ‖ 16-byte random nonce)` to calendar servers. The nonce keeps the commitment itself private from calendars.
- **Proof file.** The client produces a standard detached `.ots` proof. Offline verification evaluates every operation path and reports either *pending at calendar X* or *Bitcoin block N must have merkle root M*. The user compares M against `bitcoin-cli getblockheader` from **their own** node. CyberMesh does not ship block headers and does not trust a third party for that comparison.
- **Robustness.** Parsing has depth, node and byte budgets (an amplification attack found in review is fixed). Varint and attestation decoding is strict. `upgrade` only contacts calendars from the configured allowlist, makes at most 16 requests, and never traverses data it has just fetched.
- **Test coverage.** Tests use a local mock calendar, and two real proofs checked offline.
  - **Reference client, checked on 2026-11-22** (`opentimestamps-client` 0.8.0, public calendars). `cybermesh anchor commit --adapter ots` stamped a checkpoint with three public calendars (`alice.btc.calendar.opentimestamps.org`, `bob.btc.calendar.opentimestamps.org` and `finney.calendar.eternitywall.com`). The reference client's `ots info` read the proof: its file hash equals the commitment, and it lists those three pending attestations. In the other direction, `ots stamp` of a file gave a proof (four pending calendars) that CyberMesh parses and verifies against the file's SHA-256. Both proofs are kept as test vectors (`crates/cybermesh-anchor/tests/vectors/`), and CyberMesh writes its own proof back byte for byte.
  - **Not checked.** Both proofs were still pending. Upgrading a proof to a Bitcoin attestation (hours later) with `upgrade`, and checking a Bitcoin attestation against a node, were not done: `ots verify` needs one.

## 3. Why not a smart-contract attestation service (e.g. Ethereum Attestation Service)?

| Criterion | Signed transparency log alone | + OpenTimestamps | EAS on an EVM chain |
|---|---|---|---|
| Detects split view / rewriting by log operator | Only with independent witnesses or gossip | Yes (third-party timestamp of each checkpoint) | Yes |
| Proves time independently | No | Yes (Bitcoin block time, hours of latency) | Yes (minutes) |
| Cost per anchor | 0 | 0 (calendars aggregate) | Gas (variable, non-zero) |
| Keys/wallets to manage | Signing keys | None | Funded account + key management |
| Data put on-chain | — | 32-byte hash, aggregated, nonce-blinded | Attestation record (schema, attester address, data) |
| Token exposure | None | None | Requires a native token for gas |
| Offline verification | Yes | Yes (with own Bitcoin headers) | Needs chain data or an RPC provider |
| Operational dependency | None | Calendars (optional) | RPC provider, chain liveness |

**Decision.** The integrity mechanism is the **signed transparency log**. **OpenTimestamps** is the smallest effective optional anchor:
- it costs nothing and needs no wallet or token;
- it puts only a blinded hash on-chain, and verification is standard and offline.

EAS (or any smart contract) would add gas costs, key and wallet management, a token dependency and an RPC dependency, without improving protection. It is not used.

**Is a blockchain needed at all?** For the MVP, no. A transparency log with **independent witnesses** (organisations cross-signing checkpoints, as Certificate Transparency and the C2SP witness ecosystem do) provides the split-view protection, and the participating organisations exist anyway. Bitcoin anchoring adds a time proof and a witness that cannot be pressured. That is useful for disputes, for example "was this domain listed before date D?", but optional. Witness co-signing is on the roadmap. It would make the public-chain anchor a convenience rather than a requirement.

## 4. Commands

```bash
cybermesh anchor append --log anchor-log.json --log-id <net> --release release-1.json
cybermesh anchor commit --log anchor-log.json --log-id <net> --adapter local --chain anchor-chain.json --out receipt.json
cybermesh anchor commit --log anchor-log.json --log-id <net> --adapter ots --out receipt-ots.json   # contacts public calendars
cybermesh anchor prove  --log anchor-log.json --log-id <net> --release release-1.json --out proof.json
cybermesh anchor verify --proof proof.json --receipt receipt.json --release release-1.json [--chain anchor-chain.json]
```

# CyberMesh protocol, version 1

This document specifies the wire formats and validation rules implemented in
`crates/cybermesh-protocol`, `crates/cybermesh-crypto` and `crates/cybermesh-intelligence`.
Where this text and the code disagree, the code and its tests are authoritative; please
report the discrepancy.

## 1. Encoding

### 1.1 Canonical JSON
- **Encoding.** A payload is compact JSON (no insignificant whitespace). Fields appear in the order of the struct definitions below.
- **Maps.** Maps are ordered by key (byte order).
- **Numbers.** Only unsigned or signed integers are allowed. Floats never appear.
- **Strings.** Strings are UTF-8, and only characters that JSON requires to be escaped are escaped.
- **Unknown fields.** Unknown fields are rejected.
- **Re-encode check.** On receipt, the decoder re-encodes the parsed value and rejects the input unless the bytes are identical. This removes alternative encodings of the same value.

### 1.2 Digests
- **Format.** Digests are written `sha256:<64 lowercase hex>`.
- **Domain separation.** Domain-separated hashing is `SHA-256(tag ‖ 0x00 ‖ (len_be64(part) ‖ part)*)`. The tags used are:
  - `cybermesh/task-input/v1`
  - `cybermesh/assessments/v1`
  - `cybermesh/evidence-source/v1`
  - `cybermesh/anchor-checkpoint/v1`
  - `cybermesh/localchain-block/v1`
  - `cybermesh/assign/v1`

### 1.3 Keys and identifiers
- **Keys.** Ed25519 public keys are written as 64 lowercase hex characters.
- **KeyId.** A `KeyId` is the lowercase hex SHA-256 of the raw 32-byte public key.
- **libp2p PeerId.** The PeerId is derived from the same Ed25519 key. Transport signatures (Noise, gossipsub) use libp2p's own domain prefixes, and payload signatures use DSSE PAE, so the two cannot be confused.
- **Verification.** Signatures are verified with `verify_strict` (RFC 8032 with cofactorless strict checks; weak keys are rejected).

### 1.4 DSSE envelope

```json
{"payloadType":"application/vnd.cybermesh.task+json;v=1",
 "payload":"<standard base64, padded>",
 "signatures":[{"keyid":"<KeyId>","sig":"<base64 of 64-byte Ed25519 signature>"}]}
```

The signed message is `PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body`.

**Verification rules:**
- The envelope is at most `max_envelope_bytes`.
- It carries 1–16 signatures.
- `payloadType` must equal the expected type exactly.
- Signatures with unknown, malformed or duplicate key ids are ignored.
- At least `threshold` distinct trusted keys (≥ 1) must verify.
- Network messages (task, result, heartbeat) must carry **exactly one** signature.

| Payload type | Message | Signed by |
|---|---|---|
| `application/vnd.cybermesh.task+json;v=1` | `TaskAnnouncement` | member with role `issuer` |
| `application/vnd.cybermesh.result+json;v=1` | `TaskResult` | member with role `worker` |
| `application/vnd.cybermesh.heartbeat+json;v=1` | `Heartbeat` | member with role `worker` |
| `application/vnd.cybermesh.manifest+json;v=1` | `TrustManifest` | governance threshold |
| `application/vnd.cybermesh.appeal-decision+json;v=1` | `AppealDecision` | governance threshold |
| `application/vnd.cybermesh.verification+json;v=1` | `VerificationRecord` | member with role `verifier` |
| `application/vnd.cybermesh.release+json;v=1` | `ThreatRelease` | release-signer threshold of distinct operators |

## 2. Trust manifest

```text
TrustManifest {
  v: 1, network_id, sequence: u64, issued_at, expires_at,
  operators: [ { id: OperatorId, name } ],
  members:   [ { label, operator, public_key, roles: ["worker"|"issuer"|"verifier"] } ],
  release_signers: { threshold: u8, keys: [ { label, operator, public_key } ] },
  revocations: [ { key_id, revoked_at, reason } ]
}
```

**Validation:**
- The manifest carries signatures from at least `GovernanceRoot.threshold` pinned governance keys.
- The network id must match.
- `sequence` must be ≥ the last accepted sequence.
- The time constraints are `issued_at ≤ now + 300 s`, `now < expires_at`, and a lifetime of at most 400 days.
- Operator ids are unique, and members reference known operators.
- Every member has at least one role, and member keys are unique.
- The release-signer threshold lies in `1..=n`.
- Revoked keys hold no role anywhere.

`OperatorId` is 2–32 characters from `[a-z0-9-]`. The `GovernanceRoot { network_id, threshold, keys, min_sequence? }` is pinned out of band in node configuration and in consumers. Nodes refuse manifests below `min_sequence` (default 0) and below the highest sequence they have stored, so an old manifest cannot be replayed even to a node with an empty state directory.

## 3. Tasks

```text
TaskAnnouncement {
  v: 1, network_id, task_id: 32 hex, attempt: u32, kind: "domain-risk-assessment",
  issuer: KeyId, issued_at, expires_at, nonce: 32 hex,
  engine: { name, version }, evidence: { source_id: Digest },
  domains: [normalised domain, sorted, unique, 1..=64],
  assignees: [KeyId, unique, 1..=16, all enrolled workers],
  min_operators: u8  (1..=distinct operators among assignees)
}
```

**Domain syntax:**
- 1–253 bytes, at least 2 labels, each label 1–63 characters from `[a-z0-9-]`, no leading or trailing hyphen.
- The final label is not numeric, which excludes IPv4 literals.
- IDNs appear in punycode form.

**Time constraints:**
- `issued_at ≤ now + 120 s`
- `now < expires_at`
- `0 < expires_at − issued_at ≤ 3600 s`

**Input digest:**
`input_digest = H_tag("cybermesh/task-input/v1", canonical({kind, engine, evidence, domains}))`. Assignment and timing do not affect it.

## 4. Results

```text
TaskResult {
  v: 1, network_id, task_id, attempt, task_digest: SHA-256(task payload bytes),
  input_digest, worker: KeyId, operator: OperatorId,
  engine, evidence, assessments: [DomainAssessment sorted by domain],
  completed_at, nonce, usage: { cpu_micros, wall_micros }
}
DomainAssessment { domain, risk_score_bp: 0..=10000, confidence_bp: 0..=10000,
                   verdict: "malicious"|"suspicious"|"no-signal"|"known-benign",
                   findings: [ { code, points: i32, detail: ≤200 bytes } ≤32 ] }
```

**Stateless rules** (applied by `verify_result`):
- The signer equals `worker`.
- `operator` equals the manifest operator of the signer.
- `completed_at ≤ now + 120 s`.
- Domains are sorted and unique, and scores are in range.

**Binding rules** (applied by `TaskVerifier`):
- `task_id` and `attempt` match.
- `task_digest` matches the published task bytes.
- The signer is an assignee.
- The result arrives no later than `expires_at` plus the grace period.
- `engine` and `evidence` equal the task pins.

**Signed inconsistencies** are recorded as faults, not mere rejections:
- a wrong `input_digest` (`wrong-input-digest`);
- a domain list that differs from the task (`domain-set-mismatch`);
- two different results from one worker for one task (`equivocation`), which is also detected after settlement;
- assessments that differ from the verifier's recomputation (`incorrect-result`).

`assessments_digest = H_tag("cybermesh/assessments/v1", canonical(assessments))` is the value compared across operators. Timestamps, nonces and usage are excluded from it.

## 4a. CT shard scans

```text
CtScanTask { v: 1, network_id, task_id, attempt, issuer, issued_at, expires_at, nonce,
             engine, evidence, log_id: [a-z0-9.-]{1,64}, first_tile: u64, tile_count: 1..=16,
             assignees, min_operators }
CtScanResult { v: 1, network_id, task_id, attempt, task_digest, input_digest, worker, operator,
               engine, evidence, log_id, tiles: [TileScanResult consecutive, one per task tile],
               completed_at, nonce, usage, fetched_bytes }
TileScanResult { tile_index, leaf_count: 256, root: RFC 6962 MTH of the tile's leaf hashes,
                 unparsed: u16, names: u32 <= 8192, names_digest,
                 matches: [CtMatch sorted by (index, name)] <= 16, at most 4 per index,
                 truncated }
CtMatch { index (global entry index within the tile), name (normalised), risk_score_bp,
          verdict, codes: [FindingCode] }
```

- **Payload types.** `application/vnd.cybermesh.ct-task+json;v=1` and `application/vnd.cybermesh.ct-result+json;v=1`. Both travel on the same gossip topics as domain tasks.
- **Input digest.** `input_digest = H_tag("cybermesh/ct-task-input/v1", canonical({engine, evidence, log_id, first_tile, tile_count}))`.
- **Leaf hash.** `SHA-256(0x00 || 0x00 || 0x00 || TimestampedEntry)`: the RFC 6962 leaf prefix, then `MerkleTreeLeaf` version and type.
- **Tile root.** It equals the log's level-1 hash tile entry for that data tile.
- **Names digest.** `SHA-256("cybermesh/ct-names/v1" || 0x00 || for each name: index (u64 BE) || len(name) (u64 BE) || name)`, over every normalised name of every parsed entry in entry order, then sorted and de-duplicated per entry, up to 8,192 names.
- **Match selection.** Matches are capped at 4 per entry and 16 per tile. The kept matches are the highest by (risk descending, index, name). They are then sorted by (index, name). `truncated` is true when any cap applied.
- **Entries.** Every `TileLeaf` must carry a `leaf_index` extension equal to its position.
- **Heartbeats.** Heartbeats carry `capabilities: [TaskKind]`. Only workers advertising `ct-shard-scan` are assigned CT shards.
- **Verification records.** Records of CT tasks carry `ct: {log_id, first_tile, tile_count, tiles_checked_against_log, tiles_rescanned, entries, unparsed, matches, truncated_tiles, log_inconsistent_tiles}`.

## 5. Heartbeats

`Heartbeat { v, network_id, worker, operator, sent_at, nonce, state: "active"|"paused", engine, evidence, queue_depth }`. A heartbeat is accepted when `sent_at` lies in `[now − 300 s, now + 120 s]`. The coordinator assigns tasks only to workers that are active, recently seen, not quarantined, and running a compatible engine and evidence.

## 6. Verification records

`VerificationRecord` lists:
- `status` (`verified` | `disputed` | `insufficient`) and whether the verifier `recomputed`;
- the accepted results with their result and assessment digests;
- up to 64 rejected results plus an overflow counter;
- provable faults with evidence digests;
- per-domain outcomes `{classification: "block"|"warn"|"none", verdict, scores, findings, agreeing_operators, feed_corroborated, rationale}`.

Records are signed by the verifier. Release builders verify those signatures against the manifest.

**Classification:**
- **`none`:** fewer than `min_operators` agreeing operators, or the domain is popular or known-benign, or `score < warn_min (4000)`.
- **`block`:** verdict `malicious` and `score ≥ block_min (7000)`, a `feed-match` finding, the verifier's *own* evidence lists the host, and the verifier recomputed.
- **`warn`:** everything else at or above the warn threshold.

## 7. Releases

```text
ThreatRelease {
  v: 1, network_id, sequence: u64, previous: {sequence, digest} | null,
  issued_at, expires_at, generator, inputs: [record digests, sorted],
  entries: [ { indicator, scope: "host-and-subdomains", action: "block"|"warn",
               confidence: "high"|"medium", risk_score_bp, operators: u8,
               reasons: [{code, detail}] ≤16, evidence: [{kind, id, digest}] ≤16 } sorted, unique ],
  corrections: [ { indicator, kind: "appeal-upheld"|"rollback", reference, note } sorted, unique ]
}
```

**Consumer verification:**
1. The envelope is at most 16 MiB.
2. Valid signatures come from at least `threshold` **distinct operators** in the trust root.
3. `v` and `network_id` are correct.
4. The time constraints hold: `issued_at ≤ now + 300 s`, `now < expires_at`, and `0 < expires_at − issued_at ≤ 30 days`.
5. Indicators are valid, sorted and unique, and scores are at most 10000.
6. Text fields are printable ASCII within their length caps, and corrections are sorted.
7. **Anti-rollback**, given stored `{sequence, digest}`:
   - Reject a smaller sequence.
   - Reject the same sequence with a different digest (equivocation).
   - Reject a jump larger than 10⁶.
   - For `sequence = stored + 1` with a non-null `previous`, `previous` must equal the stored release.

**Matching:** the consumer looks up the exact host first, then each parent domain, and the most specific match wins.

## 8. Transport

- **Topics.** `/cybermesh/<network_id>/v1/{tasks,results,presence}` on gossipsub over libp2p TCP with Noise and Yamux.
- **Gossip settings.** Messages are signed (`ValidationMode::Strict`) and validated manually. The message id is `SHA-256(author peer id ‖ 0x00 ‖ data)`, and messages are at most 256 KiB.
- **Admission and limits.** Only allow-listed peers (manifest members) may connect. A token bucket applies per author, and each message costs `1 + size/1024`, capped at the burst size.
- **Mesh parameters.** These are set for small networks: `mesh_n = 4`, `mesh_n_low = 2`, `mesh_n_high = 8`, with flood publishing.

## 9. Test vectors

- **Standards vectors.** RFC 8032 test 1 and the DSSE PAE example are in `cybermesh-crypto`.
- **Engine golden vectors.** These are in `cybermesh-analysis/src/engine.rs`.
- **Release vectors.** For cross-language verification they are generated with `cargo run -p cybermesh-cli --features dev-tools -- dev test-vectors --out <dir>`, and committed in `apps/browser-extension/test/fixtures/` using deterministic test keys that are never valid in production.

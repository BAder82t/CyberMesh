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
| `application/vnd.cybermesh.ct-checkpoint+json;v=1` | `CheckpointObservation` | member with role `verifier` |
| `application/vnd.cybermesh.fault-proof+json;v=1` | `FaultProof` | member with role `verifier` |
| `application/vnd.cybermesh.release+json;v=1` | `ThreatRelease` | release-signer threshold of distinct operators |

## 2. Trust manifest

```text
TrustManifest {
  v: 1, network_id, sequence: u64, issued_at, expires_at,
  operators: [ { id: OperatorId, name } ],
  members:   [ { label, operator, public_key, roles: ["worker"|"issuer"|"verifier"] } ],
  release_signers: { threshold: u8, keys: [ { label, operator, public_key } ] },
  revocations: [ { key_id, revoked_at, reason } ],
  min_verifiers?: u8            // omitted when 1
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
- `min_verifiers` is at least 1. When it is above 1, it must not exceed the number of distinct operators holding a non-revoked verifier key. When it is 1, it is omitted from the encoding, so v0.1 manifests keep their bytes.
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
- two results from one worker for one task that assert different things (`equivocation`), which is also detected after settlement. The same answer signed again (a new nonce, say after a restart) is a duplicate, not equivocation: the `assessments_digest`, or the `tiles_digest` for CT, must differ;
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
- **Log authentication (verifier side).**
  - **Pinned log.** `ct-logs` evidence pins each log's `origin` and `public_key` (base64 DER SPKI, ECDSA P-256).
  - **Checkpoint.** The checkpoint must carry a note signature `— <origin> base64(keyID ‖ timestamp ‖ 0x04 0x03 ‖ len ‖ DER signature)`, where `keyID = SHA-256(origin ‖ 0x0A ‖ 0x05 ‖ LogID)[:4]` and `LogID = SHA-256(SPKI)`. Its ECDSA P-256 / SHA-256 signature must verify over the RFC 6962 `TreeHeadSignature` (`0x00 ‖ 0x01 ‖ timestamp ‖ size ‖ root`). No extension lines are allowed.
  - **Tile roots.** A tile root counts only if recomputing the RFC 6962 root of the signed size through it, with hash tiles at levels 0 and up, yields the signed root.
  - **Follow mode (coordinator).** Each newly polled checkpoint must also extend the previously accepted one: an RFC 6962 consistency proof is assembled from hash tiles and checked as in RFC 9162 §2.1.4.2.
- **Witnessing (split-view detection).** Verifiers that witness a log publish
  ```
  CheckpointObservation { v, network_id, log_id, witness: KeyId, observed_at, checkpoint }
  ```
  on the `checkpoints` topic, signed by `witness`, which must have the `verifier` role.
  - **Checkpoint.** `checkpoint` is the latest checkpoint the witness accepted (signed by the pinned key, at most an hour old, consistent with its previous one), at most 8 KiB, with the witness's C2SP `cosignature/v1` line appended: `— <name> base64(keyID ‖ time (u64 BE, seconds) ‖ Ed25519 signature)`. The name is `cybermesh/<network_id>/<witness KeyId>`, `keyID = SHA-256(name ‖ 0x0A ‖ 0x04 ‖ public key)[:4]`, and the signed message is `"cosignature/v1\ntime <time>\n"` followed by the checkpoint's origin, size and root lines.
  - **Freshness.** Observations older than an hour, or more than `max_clock_skew_secs` ahead, are ignored, and so are checkpoints signed more than a day ago.
  - **Acceptance.** A malformed message, another network, a `witness` that is not the signer, or a bad cosignature is `Reject`ed. Anything that is not proof of misbehaviour is `Ignore`d: a signer the receiver's manifest does not know as a verifier (it may lag), clock skew, a log signature that does not verify against the receiver's pinned key, or a log the receiver does not witness.
  - **Comparison.** A receiver compares each observation with its own latest checkpoint once its own tree is at least as large. It computes the root of its tree's first `size` entries, and the consistency proof from that root to its own, from hash tiles; the proof must verify against its own signed root. A different root from the peer's signed one proves a split view; equal sizes with different roots need no proof.
  - **Proof file.** `state_dir/ct-split-views/<log>-<larger>-<smaller>-<time>.json`: `{log_id, detected_at, detected_by, reported_by, observation, proof: {v, origin, larger, smaller, prefix_root, proof}}`, with notes as text and hashes in base64. `cybermesh ct verify-split-view --evidence <dir> <file>` checks it against the pinned key alone.
- **Names digest.** `SHA-256("cybermesh/ct-names/v1" || 0x00 || for each name: index (u64 BE) || len(name) (u64 BE) || name)`, over every normalised name of every parsed entry in entry order, then sorted and de-duplicated per entry, up to 8,192 names.
- **Match selection.** Matches are capped at 4 per entry and 16 per tile. The kept matches are the highest by (risk descending, index, name). They are then sorted by (index, name). `truncated` is true when any cap applied.
- **Entries.** Every `TileLeaf` must carry a `leaf_index` extension equal to its position.
- **Heartbeats.** Heartbeats carry `capabilities: [TaskKind]`. Only workers advertising `ct-shard-scan` are assigned CT shards.
- **Verification records.** Records of CT tasks carry `ct: {log_id, first_tile, tile_count, tiles_checked_against_log, tiles_rescanned, entries, unparsed, matches, truncated_tiles, log_inconsistent_tiles}`.

## 5. Heartbeats

`Heartbeat { v, network_id, worker, operator, sent_at, nonce, state: "active"|"paused", engine, evidence, queue_depth }`. A heartbeat is accepted when `sent_at` lies in `[now − 300 s, now + 120 s]`. The coordinator assigns tasks only to workers that are active, recently seen, not quarantined, and running a compatible engine and evidence.

## 6. Verification records

`VerificationRecord` lists:
- `verifier: {key, operator}`, the verifier that produced it. It is part of the signed payload, so two verifiers' records for the same task never share a digest;
- `status` (`verified` | `disputed` | `insufficient`) and whether the verifier `recomputed`;
- the accepted results with their result and assessment digests;
- up to 64 rejected results plus an overflow counter;
- provable faults with evidence digests;
- per-domain outcomes `{classification: "block"|"warn"|"none", verdict, scores, findings, agreeing_operators, feed_corroborated, rationale}`.

Records are signed by the verifier. Release builders check that:
- the envelope is signed by an enrolled, non-revoked verifier key;
- `verifier.key` is among the envelope's signers;
- `verifier.operator` is that key's operator in the manifest.

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

**Build rule (release signers):**
- **Per verifier.** For each (domain, verifier operator), the outcome of that operator's most recently verified record counts. Ties go to the stronger classification, then the smaller record digest.
- **Quorum.** A domain is listed when at least `min_verifiers` operators say `warn` or `block`. It is `block` when at least `min_verifiers` say `block`; otherwise it is `warn`. When `min_verifiers ≥ 2`, only records with `recomputed: true` count.
- **Content.** Reasons and score come from the weakest supporting outcome. Every supporting record is cited as `verification` evidence, up to the 16-reference cap.
- **Appeals.** After an upheld appeal, re-listing needs `min_verifiers` supporting `block` records verified after the decision.

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

- **Topics.** `/cybermesh/<network_id>/v1/{tasks,results,presence,records,checkpoints,faults}` on gossipsub over libp2p TCP with Noise and Yamux. Workers subscribe to `tasks`. The coordinator subscribes to `results`, `presence`, `records` and `faults`. Independent verifiers subscribe to `tasks`, `results` and `records`. Nodes that witness CT logs also subscribe to `checkpoints`: the coordinator for its followed log by default, and independent verifiers configured with `[ct_witness]`.
- **Fault proofs.** A verification record names a fault only by the digests of the worker's results, which nobody else can check. So an independent verifier also publishes, on `faults`,
  ```
  FaultProof { v, network_id, reporter: KeyId, reported_at, fault: FaultRecord, task, results }
  ```
  signed by `reporter` (role `verifier`). `task` is the issuer-signed task envelope and `results` the worker's signed result envelope(s): two for equivocation, one otherwise. Proofs older than 7 days are refused.
  - **Re-checked before any action.** The coordinator checks every proof against its own manifest (`check_fault_proof`):
    - The task is checked as of its issue, and each result must be the accused worker's for that task attempt, matching the fault's evidence digests.
    - Equivocation, a wrong input digest and a wrong domain or tile set follow from the signatures.
    - An incorrect domain result is recomputed with the coordinator's own engine and evidence, which must be those the task pins.
    - An incorrect CT result is re-scanned from the log with the coordinator's own access. Only tiles whose root its verified checkpoint proves are compared. A proof about a log the coordinator's witness has proven to show a split view is not confirmed: the coordinator cannot tell which view the worker scanned.
  - **Late equivocation.** A verifier keeps the signed task and accepted results of tasks it has settled (at most 32 MiB, oldest dropped first, until the task's expiry plus an hour). A later signed result from a worker it accepted, for the same task payload and attempt, that asserts something else is equivocation: the verifier quarantines the worker locally and publishes a proof with both results. The same answer signed again is not. One proof per worker and task.
  - **Outcomes.** A confirmed fault quarantines the worker, and the proof is kept in `state_dir/faults/peer-*.json`. A refuted or undecidable proof changes nothing.
  - **Bounds.** A fault is identified by the worker, its kind and the results it names. At most 2 checks run at once, each within 120 s of log access. Each reporter has at most 8 proofs queued, and reporters take turns, so one verifier cannot crowd out the others. A decided fault (confirmed or refuted) is not checked again; an undecided one (the log was unavailable, say) can be checked again after 300 s.
- **Record distribution.** Every verifier publishes each signed `VerificationRecord` envelope it writes on `records`. It also re-publishes those verified within the last hour every 15 minutes, which outlasts the 10-minute duplicate cache. On receipt, a verifier:
  - authenticates the record exactly as a release builder does (enrolled verifier signature, canonical record, network id, named verifier equals signer and its operator);
  - refuses its own echoes, records dated more than 300 s in the future, and records older than 30 days;
  - stores new records as `received-records/<sha256-hex>.json`, re-encoded with only the record verifier's own signature;
  - enforces quotas: 100,000 records and 1 GiB in total, 25,000 records and 256 MiB per verifier operator, and 2 records per operator and task id;
  - prunes records once they are 30 days old;
  - re-checks the store whenever a newer manifest is loaded, removing records of verifiers no longer enrolled.

  Only valid new records are forwarded (`Accept`). Provably invalid ones are `Reject`ed: malformed, wrong network, or misattributed. Anything that is not proof of misbehaviour is `Ignore`d: an unknown signer (the receiver's manifest may lag), clock skew, age, a full quota or a local write error.
- **Building from received records.** `release build` re-verifies every file against the build-time manifest, which is authoritative. Files that do not verify are skipped and named (`--strict` makes them fatal). Skipping can only remove support, never add an entry.
- **Gossip settings.** Messages are signed (`ValidationMode::Strict`) and validated manually. The message id is `SHA-256(author peer id ‖ 0x00 ‖ data)`, and messages are at most 256 KiB.
- **Admission and limits.** Only allow-listed peers (manifest members) may connect. A token bucket applies per author, and each message costs `1 + size/1024`, capped at the burst size.
- **Validation verdicts.** `Reject` means proof of misbehaviour, and is reserved for what no software version, manifest timing or clock can explain:
  - a signature by an enrolled key that does not verify;
  - a payload claiming an identity other than its signer;
  - a message for another network;
  - a result from a worker not assigned the task, or already faulted on it;
  - a proven fault (equivocation, a wrong input digest, the wrong domains or tiles);
  - a record naming an enrolled verifier that did not sign it.

  Anything an honest node can produce is `Ignore`d:
  - messages that are expired or dated ahead (clocks);
  - a signer, role, assignee or operator the receiver's manifest does not have yet (`NotAuthorized`, `ManifestMismatch`);
  - bytes this version cannot decode, or limits it does not allow (a newer release adds fields or raises limits);
  - a result that is late, for another attempt or task payload, or computed with another engine or evidence;
  - a witness cosignature that does not verify;
  - replays and quotas.

  Messages from authors not in the receiver's allowlist are also `Ignore`d.
- **Peer scoring.** Penalty-only (`cybermesh_network::peer_scoring`).
  - **Author penalties.** A `Reject`ed message counts against its **author**, never against the peers that relayed it: gossipsub itself is told `Ignore`, since it would charge every peer that delivered a copy. The count halves every 10 minutes and sets the author's score, which gossipsub receives as its application score:
    - below 1.5, the score is 0, so one invalid message is tolerated;
    - from 1.5, it is −40: out of the mesh and no gossip, but publishing still reaches the peer;
    - from 2.5, it is −100: graylisted. Gossipsub ignores everything the peer sends, including what it relays for others, and this node drops every message it authored before validation, whichever peer relays it.
  - **Gossipsub's own checks.** A broken gossipsub message signature costs the delivering peer `10 × n²`. Protocol misbehaviour (re-grafting during backoff, broken gossip promises) costs as in gossipsub, beyond a tolerance of 6.
  - **Thresholds.** −10 (gossip), −50 (publish) and −80 (graylist).
  - **Not scored.** Time in the mesh, message deliveries, IP colocation and slowness.
  - **Persistence.** Gossipsub scores outlive a reconnection by an hour, and author counts are kept regardless of connections.
- **Mesh parameters.** These are set for small networks: `mesh_n = 4`, `mesh_n_low = 2`, `mesh_n_high = 8`, with flood publishing.

## 9. Test vectors

- **Standards vectors.** RFC 8032 test 1 and the DSSE PAE example are in `cybermesh-crypto`.
- **Engine golden vectors.** These are in `cybermesh-analysis/src/engine.rs`.
- **Release vectors.** For cross-language verification they are generated with `cargo run -p cybermesh-cli --features dev-tools -- dev test-vectors --out <dir>`, and committed in `apps/browser-extension/test/fixtures/` using deterministic test keys that are never valid in production.

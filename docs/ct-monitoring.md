# Certificate Transparency monitoring (`ct-shard-scan`)

Phishing sites almost always need a TLS certificate. Every publicly trusted certificate is
recorded in public Certificate Transparency (CT) logs before browsers accept it. Scanning
newly logged certificates for names that look like a protected brand (`paypa1-…`,
`xn--pypal-4ve.com`, …) gives security teams an early signal, often before the site is live.

CyberMesh splits this work across organisations. Workers scan distinct shards of public CT
logs, and the network verifies their work without redoing all of it. The verified results
feed an **investigation report** for brand owners and security teams. Publishing CT findings
as browser warnings is possible but **off by default** (see §5).

## 1. Task

A `ct-shard-scan` task (payload type `application/vnd.cybermesh.ct-task+json;v=1`) contains:

- a log id from the pinned **`ct-logs`** evidence;
- a range of 1–16 consecutive **full** data tiles of the log (256 entries per tile);
- the usual issuer signature, assignees, deadlines, engine version and evidence pins.

The worker:

1. fetches each data tile (`<monitoring prefix>/tile/data/<N>`, C2SP `static-ct-api`) **only** from the monitoring URL in the pinned evidence;
2. parses each `TileLeaf`, requires its `leaf_index` extension to equal the entry's position, and computes the RFC 6962 leaf hash `SHA-256(0x00 ‖ 0x00 ‖ 0x00 ‖ TimestampedEntry)`;
3. extracts SAN `dNSName`s and subject CNs from certificates and precertificate TBSCertificates (`x509-parser`), then lowercases them, removes `*.` and normalises them;
4. runs the deterministic engine on every name and keeps names with a **brand signal** (`brand-impersonation`, `brand-lookalike`, `idn-homograph`);
5. reports per tile, signed (`application/vnd.cybermesh.ct-result+json;v=1`):
   - the **Merkle root of the 256 leaf hashes**;
   - the number of names and a **digest of every (entry index, name) pair**, so a worker cannot skip parsing tiles that have no matches;
   - the matches, sorted by (entry index, name).

Outputs are deterministic, so honest workers scanning the same shard produce byte-identical results.

**Caps.** At most 8,192 names per tile, 4 matches per certificate and 16 matches per tile. When a cap applies, matches are kept by priority (highest risk first), so a certificate full of decoy brand names cannot push a strong lookalike out. The tile is then marked `truncated`, and `cybermesh ct report` lists it as incomplete. With these caps the largest possible result (16 tiles, all saturated with 253-character names) is 181,928 bytes, inside the 256 KiB message limit (`worst_case_result_fits_the_envelope_limit`).

## 2. Safety and consent

- **Opt-in.** A worker accepts CT tasks only if its operator sets `ct_scanning = true`. Workers advertise the capability in their signed heartbeats, and the coordinator assigns CT shards only to workers that advertise it.
- **Pinned egress only.** Tasks never contain URLs. The only reachable endpoints are the `checkpoint` and `tile/...` paths under monitoring prefixes listed in the governance-pinned `ct-logs` evidence.
  - Prefixes must be HTTPS. Plain HTTP is allowed for loopback, for tests and demos only.
  - Requests never follow redirects, and only HTTP 200 responses are used.
  - Responses are capped at 16 MiB after decompression, and requests time out after 30 s. Hash tiles must have exactly the expected length.
  - Operators can restrict outbound traffic to those log hosts at their firewall.
- **No contact with lookalike domains.** Workers download public log data. They never resolve or contact the names they find.
- **Budgets.** CT downloads have their own budget (`ct_fetch_kib_per_sec`, default 256 KiB/s). The scan runs on a background thread, one task at a time. It waits while the governor pauses or throttles the worker, so the CPU budget applies to it. It stops on STOP, on shutdown and when the task expires.

## 3. Verification

Recomputing every shard would make the workers pointless, so the verifier combines four cheap checks:

| Check | What it catches | Cost |
|---|---|---|
| **Log commitments.** Each claimed tile root must equal the log's own root for that tile, *proven against the log's signed checkpoint* (see "Trusting the log" below). A mismatch is a fault only after the verifier's own scan of that data tile matches the proven root. | A worker that did not download or process the log's real entries | A few small hash tiles per task, plus one data tile per mismatch |
| **Spot checks.** The verifier re-scans `spot_check_tiles` tiles per task (default 2), chosen from a secret seed: one uniformly, one among tiles that some worker reported matches for. Whole tile results are compared, including the names digest. | Omitted, altered or fabricated matches; skipped parsing | 2 of 8 tiles at the default shard size |
| **Cross-operator agreement.** Each shard goes to `replication` workers of distinct operators (default 2), and any disagreement triggers a full rescan by the verifier. | One lying operator | Only on disagreement |
| **Confirm before publish** (only when publishing is enabled). Every tile whose matches would become a warning is re-scanned before publication. | Fabricated findings, even by colluding operators | Proportional to findings, not to volume |

Workers whose signed results differ from the log or from the verifier's rescan get a provable `incorrect-result` fault and are quarantined. Without access to the log, the verifier cannot settle disagreement: the task is recorded as `disputed` and nothing is published.

**Trusting the log.** The log's signature, not HTTPS, is the root of trust.
- **The checkpoint.** It must carry a valid RFC 6962 `TreeHeadSignature` (ECDSA P-256) by the log's **pinned key**, encoded as a C2SP note signature. Its origin must equal the **pinned origin**.
  - Key and origin come from the `ct-logs` evidence. For real logs they are taken from Google's CT log list v3 (`datasets/ct-logs/public-static-ct-logs.json`).
  - Signature lines from unknown keys (witnesses, other key types) are ignored.
  - A bad signature by the pinned key rejects the checkpoint.
- **Each tile root.** It is proven by recomputing the tree root of the signed size *through* that tile's level-1 entry, using the other hashes from the log's hash tiles at levels 0 and up. The result must equal the signed root.
- **What this buys.** A CDN, mirror or network attacker can no longer substitute hash tiles or a checkpoint.
- **When verification fails.**
  - A checkpoint that does not verify, or is more than an hour old, or is dated in the future, means no log access: disagreement is disputed and nothing is confirmed.
  - A tile whose root cannot be proven (hash tiles unavailable) leaves the task `insufficient`, to be retried. The verifier's own rescan of such a tile is not used against workers, so withholding hash tiles and forging a data tile cannot get honest workers faulted.
  - Partial hash tiles that the log has deleted after completing them are read from the full tile, as the spec allows.
- **Validation.** Validated on real logs (2026-11-17): Let's Encrypt Willow 2027h1 (1.23 billion entries) and Google ParcelYard 2027h1 (865 million). Their checkpoints verified with the pinned keys, and every scanned tile root was proven against them in about 0.5 s per tile, including hash-tile fetches.

**Inconsistent logs.** Two cases count as the log (or its CDN) serving inconsistent data:
- its hash tiles for a tile contradict its own signed checkpoint;
- the data tile the verifier downloads does not hash to the proven root.

Nobody is faulted, the tile is listed in `log_inconsistent_tiles`, and the task is `disputed`. If workers agree on a root that differs from the log and the verifier cannot fetch the tile to settle it, the task is not verified either.

**Residual risk.**

- Two colluding operators that omit the *same* real match, and report the tile as empty, are caught only by the uniform spot check: probability 1/`tile_count` per task (1/8 by default). Omission hides a finding; it cannot create a false one.
- Colluders that fabricate a match for the investigation report (publishing off) are caught when that tile is spot-checked. The second check is drawn from tiles that report matches. In `spot_checks_favour_tiles_with_reported_matches` (4-tile tasks, 3 tiles with matches) they were caught in 39 of 64 seeded runs, against 1 in 4 for a single uniform check. With publishing on, every published finding is confirmed anyway.
- **Split views are not detected.** A log that signs *different* trees for different viewers would not be detected by one verifier alone. Witness cosignatures (C2SP `tlog-witness`) are on the roadmap.

## 4. Measurements on real CT data (2026-11-17)

These are one-off measurements with `cargo run -p cybermesh-ct --features http --example scan_log`. They are ordinary monitor traffic and were not repeated in automated tests.

| Log (static CT API) | Tiles | Entries | Unparsed | Tile roots equal to the log's | CPU per entry | Decoded bytes per entry | Brand signals |
|---|---|---|---|---|---|---|---|
| Let's Encrypt Willow 2026h2 | 20 | 5,120 (191/256 precertificates in the first tile) | 0 | 20/20 | 105 µs | 2,053 B | 12 (engine 0.3.0) |
| Let's Encrypt Willow 2027h1 | 40 | 10,240 (15,625 names) | 0 | 40/40 | 70 µs | 1,543 B | 417 (engine 0.4.0) |

- **Transfer.** A full tile is 165 KB on the wire with gzip, versus 523 KB uncompressed: about 645 B per entry.
- **Total volume.** All 63 usable or qualified tiled logs in Google's CT log list grew by about **243 million entries per day**, measured over 60 s.
- **What the brand signals are.** In the 2027h1 sample, most of the 417 signals were `*.fabric.microsoft-int.com`, which is Microsoft's own infrastructure. The brand table lists `microsoft.com` and related domains but not `microsoft-int.com`, so these look like impersonation. The 2026h2 sample showed `cloud.*` matching the token `icloud`, which was fixed in engine 0.4.0.
- **Conclusion.** On real data, *brand token appears in a name* is dominated by the brand owners' own services. CT findings are therefore investigation material by default, not warnings.

## 5. Publication policy

| Setting (`[ct.policy]`) | Default | Meaning |
|---|---|---|
| `publish_warnings` | `false` | When false, CT findings appear only in `cybermesh ct report`. |
| `publish_min_score_bp` | `7000` | When publishing, the minimum score from the verifier's own assessment. |
| (fixed) | — | A published finding needs a `brand-lookalike` or `idn-homograph` signal. A brand token alone is never enough. |
| (fixed) | — | CT findings are capped at `warn`, never `block`, even for feed-listed names. |
| `min_operators` | `2` | Distinct operators that must agree on a shard. |
| `spot_check_tiles` | `2` | Tiles re-scanned per task (the first uniformly, the second among tiles that report matches). |
| `check_log_roots` | `true` | Compare every tile root with the log's root for that tile, proven against its signed checkpoint. |

## 6. Does donated capacity help here?

| | Lexical domain checks | CT monitoring, all tiled logs |
|---|---|---|
| CPU per item | about 20–30 µs | about 70–105 µs |
| Volume | ad hoc batches | about 243 M entries/day |
| Continuous CPU | negligible | about 0.2–0.3 of one core |
| Bandwidth | none | about 157 GB/day gzip (about 15 Mbit/s) |
| Workers at a 1 % CPU budget | one is enough | about 20–30 (40–60 with 2× replication) |
| Verifier cost | full recomputation (cheap) | hash tiles (about 30 MB/day) + 2/8 spot checks + confirmations |

CT monitoring is the first CyberMesh workload large enough that pooling many small donated slices is a natural fit, and the verifier needs only a fraction of the work. **A single dedicated server with about a third of a core and about 15 Mbit/s could also do it.** The decentralised version's value is independent verification by several organisations and not depending on one provider, not raw capacity.

## 7. Using it

```bash
# Pin logs in the evidence bundle (see datasets/ct-logs/public-static-ct-logs.json for real ones)
cybermesh evidence pin --dir <evidence>
cybermesh ct checkpoint --evidence <evidence> --log <log-id>
cybermesh ct scan --evidence <evidence> --log <log-id> --tiles 4        # one-off local scan
cybermesh ct report --records state/coordinator/records --manifest manifest.json \
  --root governance-root.json --evidence evidence --out ct-report.json   # per-brand investigation report
```

Coordinator (`coordinator.toml`):

```toml
[ct]
log_id = "letsencrypt-willow-2027h1"
tile_count = 64          # omit first_tile to scan the most recent full tiles
tiles_per_task = 8
replication = 2

[ct.policy]
publish_warnings = false # investigation report only (recommended)
```

Worker (`[resources]` in `worker.toml`): `ct_scanning = true` and `ct_fetch_kib_per_sec = 256`.

## 8. Limitations and next steps

- **Static CT API only.** RFC 6962 `get-entries` logs are not supported.
- **Parser version is part of the engine version.** `x509-parser` is pinned to `=0.18.1` and recorded in `ENGINE_VERSION`, because it determines which names are extracted.
- **No witnesses yet.** Checkpoints are verified against the log's pinned key and tile roots are proven against them. Checkpoints are not yet cosigned by independent witnesses, so a log showing different trees to different viewers (a split view) goes undetected.
- **Pinned keys must be maintained.** When a log's key or URL changes, the `ct-logs` evidence (and its pin) must be updated, as for any evidence.
- **Brand table.** The table needs owner-maintained "own infrastructure" lists, for example `microsoft-int.com`, before CT warnings can be enabled responsibly.
- **Verifiers.** Independent verifiers check CT shards with their own log access and their own secret spot-check seeds, so their spot checks are independent of the coordinator's. A published CT warning needs the manifest's `min_verifiers` verifier operators.
- **No continuous tailing.** The coordinator scans a configured range or the most recent tiles at start-up. Tailing new tiles continuously is the next step.

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
- **What this buys.** A CDN, mirror or network attacker can no longer substitute hash tiles or a checkpoint. In follow mode, each new checkpoint must also provably extend the previous one, so a log that rewrites its history is detected over time.
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
tile_count = 64          # omit first_tile to start at the most recent full tiles
tiles_per_task = 8
replication = 2
follow = true            # keep following the log as it grows (otherwise: scan once)
poll_secs = 60           # checkpoint poll interval
max_tiles_per_poll = 256 # new tiles scheduled per poll at most
# until_tile = 5000000   # optional: stop (with exit_when_done) once tiles below this are settled

[ct.policy]
publish_warnings = false # investigation report only (recommended)
```

**Following a log.** With `follow = true` the coordinator polls the log's checkpoint every `poll_secs` and schedules each newly completed full tile.
- **Which checkpoints are accepted.** A checkpoint is accepted only if it is signed by the pinned key, at most an hour old, and **proven to extend the previous one**. The proof is an RFC 6962 consistency proof assembled from the log's hash tiles, and both signed roots are recomputed from it.
  - A validly signed checkpoint that does not extend the previous one means the log rewrote its history, or is showing different trees to different viewers. It is counted (`ct_log_inconsistencies`) and logged, and the coordinator keeps the old head and schedules nothing from it.
  - After 3 such checkpoints in a row, following **halts** (`ct_follow_halted`). A bounded run then ends and `coordinator run` exits with an error. After investigating, `cybermesh ct follow-reset --state <state_dir>/ct-follow.json` clears the saved head while keeping the resume point.
  - A smaller, older checkpoint (a lagging mirror) is only treated as stale.
  - Pending tasks are verified against a checkpoint that must itself extend the followed head, never against a forked view.
- **Backlog limits.** At most `max_tiles_per_poll` tiles are scheduled per poll, and none while `4 × max_inflight` CT batches are already waiting. The rest wait for later polls (`ct_lag_tiles` in the report).
- **Restarts and failures.** Progress is kept in `state_dir/ct-follow.json`: the last accepted signed head and the first tile not yet **verified**. A restart resumes there and checks the next checkpoint against the saved head.
  - Batches that were abandoned (too few workers) or not verified after their attempts are scheduled again on later polls, up to 3 times.
  - Tiles still unverified after that are counted (`ct_tiles_unverified`) and keep the resume point, so a later run scans them again. Tiles are never silently skipped.
- **Live rates.** On real logs (2026-11-17), Let's Encrypt Willow 2027h1 and Google ParcelYard 2027h1 each grew by about one full tile per second. Both checkpoints in each pair verified, and the consistency proof between them took under a second (`cargo run -p cybermesh-ct --features http --example follow_log`).

Worker (`[resources]` in `worker.toml`): `ct_scanning = true` and `ct_fetch_kib_per_sec = 256`.

### Keeping the brand table current

On real CT data most brand signals are the brand owners' own services (§4). `cybermesh evidence suggest-owned-domains` finds such domains in a `ct watch` run, so a maintainer can add them to the brand's `legitimate` list:

```bash
cybermesh evidence suggest-owned-domains --run <ct watch run dir> --evidence <evidence> \
  --from-ms <start> --to-ms <end> --out suggest.json --write-brands brands.suggested.json
```

- **Rule.** A domain is suggested for a brand only if a certificate in the window also names a domain already on that brand's list, or one suggested this way. A CA validates every name on a certificate, so one that names both domains was requested by someone who controls both. This is the rule of revision 1 of the CT evaluation ([ct-evaluation.md](ct-evaluation.md) §5.1).
- **Counting certificates.** Each certificate counts once, however often it was logged: as a precertificate and as a certificate, in several logs, or reissued with the same names. Certificates are told apart by their set of names.
- **Guards.**
  - A candidate needs at least `--min-flagged` (default 10) names flagged for the brand.
  - Domains on the evidence's hosting-platform list are never suggested, because names under them belong to customers.
  - Neither is a domain whose certificates name more than `--max-co-domains` (default 100) domains the brand does not own. That marks a multi-tenant service where anyone can get a name.
  - `--min-shared` (default 1, as in revision 1) can ask for more shared certificates. Genuine links often rest on one certificate, reissued many times.
- **Domains** are grouped as the engine groups them, by the Public Suffix List including its private section. A name such as `bucket.s3.amazonaws.com` is therefore its own domain, not part of `amazonaws.com`, since anyone can create one.
- **Output.**
  - The report lists each suggestion with its evidence, and each rejected candidate with the reason.
  - It also counts input that could not be read. Unreadable lines and damaged segments are reported, and a run with no name segments, or a `matches.jsonl` with no readable line, is refused.
  - `--write-brands` writes the extended brand list for review. Outputs are refused inside the evidence or run directory, so the evidence is never changed, and an updated list must be pinned again (`cybermesh evidence pin`) like any evidence.

Suggestions are evidence for a maintainer, not a confirmation by the brand owner.

**Applied to the dev window of the CT evaluation** (days 1–2, 2026-11-18 18:05 to 2026-11-20 18:05 UTC). Only certificates logged in that window were read.
- **Input.** 1.27 million distinct certificates (3.88 million log entries) named one of the 348 domains with at least 10 flagged names for a brand. Three name segments were incomplete: those `ct watch` was still writing, past the window.
- **Suggested: 13 domains**, including the six of revision 1. Five rest on a single certificate, and those five certificates were checked by hand. For example, the one linking `microsoft-int.com` names `applications`, `apps.dev` and `identity` under both `microsoft.com` and `microsoft-int.com`, and was logged 56 times over 30 hours. The one for `cpdomaintest.in` also names `captivateprime.adobe.com`, Adobe's learning platform, and looks like its test domain.

  | Brand | Suggested domain | Flagged names | Certificates shared with the brand | Shares most with |
  |---|---|---|---|---|
  | adobe | `cpdomaintest.in` | 18 | 1 | `adobe.com` |
  | amazon | `amazonaws.com.cn` | 119,138 | 2 | `amazon.com` |
  | amazon | `amazonwebservices.com.cn` | 8,338 | 6 | `amazonaws.com.cn`, itself suggested |
  | amazon | `amazon.dev` | 2,940 | 7 | `amazon.com` (7) and 14 other Amazon domains |
  | amazon | `aws.dev` | 59 | 34 | `amazonaws.com` (31), `amazon.com` (3) |
  | amazon | `amazonoperations.app` | 30 | 1 | `amazon.com`, `amazon.dev` |
  | amazon | `a2z.com` | 11 | 22 | `amazonaws.com` (21), `amazon.com` (2) |
  | chase | `jpmchase.net` | 20 | 10 | `jpmorgan.com` (9), `chase.com` (1) |
  | microsoft | `microsoft-int.com` | 113,286 | 1 | `microsoft.com` |
  | microsoft | `microsoft.us` | 55 | 1 | `azure.com`, `microsoft.com` |
  | microsoft | `microsoft-ppe.com` | 14 | 3 | `microsoft.com` (3), `windows.net` (3) |
  | netflix | `netflix.net` | 542 | 2 | `netflix.com` |
  | netflix | `netflixstudios.com` | 26 | 1 | `netflix.com`, `netflix.net` |

- **Rejected.**
  - `sslip.io` (for 8 brands) and `nip.io` (for 3) give anyone a name for an IP address. `onmicrosoft.com` holds Microsoft 365 customers' tenant names. All three are hosting platforms. A first version of the command without this guard suggested `sslip.io` and `onmicrosoft.com` for Microsoft, which is why they are now on the list.
  - 323 shared no certificate with the brand's domains, among them `amazonaws.eu`, `amazongamelift.com` and `microsoft-falcon.net`. They stay flagged.

The 13 domains are now in `datasets/demo/evidence/brands.json`, and the three platforms in `hosting-platforms.txt`.

## 8. Limitations and next steps

- **Static CT API only.** RFC 6962 `get-entries` logs are not supported.
- **Parser version is part of the engine version.** `x509-parser` is pinned to `=0.18.1` and recorded in `ENGINE_VERSION`, because it determines which names are extracted.
- **No witnesses yet.** Checkpoints are verified against the log's pinned key and tile roots are proven against them. Checkpoints are not yet cosigned by independent witnesses, so a log showing different trees to different viewers (a split view) goes undetected.
- **Pinned keys must be maintained.** When a log's key or URL changes, the `ct-logs` evidence (and its pin) must be updated, as for any evidence.
- **Brand table.** `evidence suggest-owned-domains` proposes brand-owned domains from CT data, and the shipped table includes 13 found this way (§7). Lists confirmed by the brand owners are still needed before CT warnings can be enabled responsibly.
- **Verifiers.** Independent verifiers check CT shards with their own log access and their own secret spot-check seeds, so their spot checks are independent of the coordinator's. A published CT warning needs the manifest's `min_verifiers` verifier operators.
- **One coordinator per log.** A single coordinator follows each log. Independent verifiers check its tasks but do not poll the log themselves.

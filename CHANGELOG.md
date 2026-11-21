# Changelog

## Unreleased

### Added
- **The CT library reads classic RFC 6962 logs.** DigiCert, Cloudflare and Sectigo run classic logs (17 usable on 2026-11-21, against 63 static ones). The new `rfc6962` module presents such a log like a static one:
  - the signed tree head becomes a checkpoint that the existing verifier checks unchanged;
  - 256 entries fetched with `get-entries` form a tile that is scanned as before;
  - a tile's root is proven against the signed root with one `get-proof-by-hash` audit path: its first eight hashes must rebuild the tile root from the entries received, so every entry and its position are bound;
  - consistency between checkpoints comes from `get-sth-consistency`, including the prefix root a split-view proof needs.

  An in-memory mock classic log is included for tests. Nodes and the CLI do not use classic logs yet.
- **Independent verifiers prove late equivocation.** A verifier keeps the signed task and the accepted results of tasks it has settled (up to 32 MiB, oldest dropped first). If a worker whose result it accepted later sends a signed result that asserts something else, the verifier quarantines the worker locally and publishes a fault proof on `faults`, which the coordinator confirms from the signatures. The same answer signed again is not equivocation. Reports gain `late_faults`. See [docs/protocol.md](docs/protocol.md) §8 and threat model T30.

## v0.3.4 (2026-11-21, research pre-release)

Compatible with v0.3.x. Verifiers publish fault proofs on a new `faults` gossip topic that only the coordinator subscribes to; older nodes ignore it. This release narrows what `Reject` means (provable misbehaviour only) and what equivocation means (two different answers), so nodes on different versions may disagree on edge cases. **Not production-ready; no external audit.**

### Added
- **The coordinator acts on faults that independent verifiers prove.** An independent verifier can catch a worker the coordinator missed, because its CT spot checks use its own secret seed.
  - The verifier now publishes a fault proof on a new `faults` gossip topic. The proof carries the issuer-signed task and the worker's own signed results.
  - The coordinator re-checks each proof before quarantining the worker: from the signatures for equivocation and mismatched results, by its own recomputation for domain tasks, and by re-scanning log-proven tiles for CT tasks.
  - A false or undecidable claim changes nothing. Neither does a CT claim about a log proven to show a split view.
  - Checks are bounded: two at a time, 120 s of log access each, and eight queued per reporter, with reporters taking turns.
  - Reports gain the proof counters, and confirmed proofs are kept in `state_dir/faults/`.
  - See [docs/protocol.md](docs/protocol.md) §8 and threat model T30.
- **Penalty-only peer scoring.** A message the application `Reject`s now counts against its **author**, never against the peers that relayed it.
  - One invalid message is tolerated, so a false positive costs an honest node nothing.
  - About two within ten minutes take the author out of the mesh and stop gossip with it.
  - About three graylist it: everything it authors is dropped, whichever peer relays it, until its count decays (it halves every 10 minutes).
  - Nothing can be earned, so good behaviour cannot be banked against attacks.
  - Reports include `net_penalised_peers`.

  See [docs/protocol.md](docs/protocol.md) §8 and threat model T29.

### Changed
- **Ownership.** CyberMesh is copyright 2026 VaultBytes Innovations Ltd. A `NOTICE` file states this, as do the README, the crates' `authors` field and the browser extension package. The licence remains Apache-2.0.
- **`Reject` now means proof of misbehaviour, and only that.** It is reserved for what no software version, manifest timing or clock can explain:
  - a signature by an enrolled key that does not verify (now reported as a bad signature, not as an unknown signer);
  - a payload claiming an identity other than its signer;
  - another network;
  - results from unassigned or faulted workers;
  - proven faults;
  - records naming an enrolled verifier that did not sign them.

  Now `Ignore`d:
  - expired or future-dated messages;
  - signers, roles, assignees or operators a lagging manifest does not have yet (new `ProtocolError::ManifestMismatch`);
  - bytes this version cannot decode, or limits it does not allow;
  - results that are late, for another attempt or task payload, or computed with another engine or evidence;
  - unusable witness cosignatures;
  - messages from authors outside the receiver's allowlist.

  `ProtocolError::proves_misbehaviour` decides. `SubmitOutcome::Rejected` carries a `Rejection { reason, misbehaviour }`, and rejected results are still listed in verification records as before.
- **Equivocation means two different answers.** Two signed results from one worker for one task are equivocation only if they assert different things (their `assessments_digest`, or `tiles_digest` for CT, differ). The same answer signed again, for example by a worker re-running a task after a restart, is now a duplicate. This applies within a task and after settlement.

## v0.3.3 (2026-11-21, research pre-release)

Compatible with v0.3.x. The wire protocol is unchanged, apart from a new `checkpoints` gossip topic that only nodes witnessing CT logs subscribe to; others ignore it. The demo evidence bundle changes (brand list and hosting platforms), so nodes that share tasks need the same bundle. **Not production-ready; no external audit.**

### Added
- **CT log witnessing: split views are caught between organisations.** A log could show different organisations different trees, each consistent on its own; one organisation cannot see that alone.
  - Verifiers now witness logs. Each polls a log's checkpoint, accepts it only if signed, fresh and consistent with its previous one, cosigns it (C2SP `cosignature/v1`, Ed25519) and publishes it on a new `checkpoints` gossip topic.
  - Each witness compares the others' checkpoints with its own view, using hash tiles authenticated against its own signed checkpoint. Two checkpoints the log signed that cannot belong to one append-only log are written to `state_dir/ct-split-views/` as a proof anyone can check offline: `cybermesh ct verify-split-view`.
  - The log is then no longer relied on: following halts, and its CT tasks are settled without log access.
  - The coordinator witnesses its followed log by default (`[ct] witness`). Independent verifiers opt in with `[ct_witness] logs = [...]`.
  - Threat model T28; [docs/ct-monitoring.md](docs/ct-monitoring.md) §3. Wire-compatible: nodes that do not witness ignore the new topic.
- `cybermesh evidence suggest-owned-domains` finds domains that brand owners run themselves among the names a `ct watch` run flagged, so they can be added to the brand's `legitimate` list.
  - It uses the shared-certificate rule of CT evaluation revision 1, counting each certificate once however often it was logged or reissued.
  - It never suggests a hosting platform or a multi-tenant service.
  - It reports input it could not read and refuses a run without name segments.
  - It only reports. `--write-brands` writes an extended brand list for review, and outputs inside the evidence or run directory are refused.

  See [docs/ct-monitoring.md](docs/ct-monitoring.md) §7.

### Changed
- **Demo evidence** (sources dated 2026-11-20).
  - `brands.json` adds 13 brand-owned domains that the command found in days 1–2 of the CT evaluation: six for Amazon (including `amazonaws.com.cn` and `amazon.dev`), three for Microsoft (including `microsoft-int.com`), two for Netflix, `jpmchase.net` for Chase and `cpdomaintest.in` for Adobe. Re-scored on those days, the list flags 73.5 % fewer names at warn level than v0.3.2's (87,700 instead of 330,621), with no detection lost ([docs/ct-monitoring.md](docs/ct-monitoring.md) §7).
  - `hosting-platforms.txt` adds `onmicrosoft.com`, `nip.io` and `sslip.io`, where names belong to customers.
  - The bundle's pins change, so nodes that share tasks need the same bundle. The running CT evaluation is unaffected: it is scored with the bundle it started with and with the frozen revision 1.

### Fixed
- `docs/ct-evaluation.md` §5.1 gave log-entry counts as certificate counts for the revision 1 domains. A correction note gives the distinct certificates, from 1 to 10 per domain. The rule needs one, so the selection is unchanged.

## v0.3.2 (2026-11-20, research pre-release)

Compatible with v0.3.x: the wire protocol and evidence formats are unchanged. Host names in peer addresses are a node-local configuration option, and nodes on v0.3.1 still interoperate but need IP addresses. **Not production-ready; no external audit.**

### Added
- **CT evaluation, revision 1 frozen** ([docs/ct-evaluation.md](docs/ct-evaluation.md) §5.1).
  - Six brand-owned domains were added to the brand lists, chosen from the dev window by a shared-certificate rule. On days 1–2 this gives 73 % fewer warn-level flags with no detection lost. The frozen list is in `docs/evaluation-results/ct-eval-rev1-brands.json`.
  - The dev-window (days 1–2) results and an analysis of the misses are in §8.1.
  - `ct evaluate` also reports observability and recall for hosts whose own name appears in a certificate. This is an added breakdown: a host covered only by a wildcard certificate can't be flagged from CT.
- **Host names in peer addresses.** Bootstrap addresses can name a peer by host name (`/dns4/`, `/dns6/`, `/dns/`), resolved with the system resolver. Only a node's own configured addresses are ever dialled, and the peer id in the address is authenticated by the Noise handshake, so a spoofed DNS answer can only make the dial fail (threat model T27). This uses libp2p's `dns` feature, which adds `hickory-resolver`.
- **Pilot kit for participating organisations.**
  - [docs/pilot.md](docs/pilot.md): the invitation, covering goals, roles, resources, timeline and what participants accept.
  - [docs/node-risk.md](docs/node-risk.md): a page for security teams on what a node contacts, holds and can be made to do, and how to stop it.
  - `deploy/systemd/cybermesh-verifier.service`: a hardened unit for independent verifiers.
  - The operator guide now starts from a verified release binary.

### Fixed
- `ct evaluate`: the tile and entry counts of a window now count only polls inside it; before, they covered the whole run so far. The whole-run totals are reported separately.
- The Linux binaries need glibc 2.34 or later (Ubuntu 22.04 included), not 2.36 as `docs/build-integrity.md` said.

## v0.3.1 (2026-11-20, research pre-release)

Compatible with v0.3.0: the wire protocol and evidence formats are unchanged, and resource reports only gain fields. It is the first release whose binaries are built reproducibly and attested in CI. **Not production-ready; no external audit.**

### Added
- **Build integrity.**
  - `.github/workflows/release.yml` builds the release binaries (Linux x86-64 and arm64 in the pinned Rust image, macOS arm64) twice each, on separate runners, and fails unless both copies are identical.
  - On a version tag it creates a SLSA build provenance attestation (GitHub artifact attestations, Sigstore) for the binaries and the SBOM, and attaches binaries, `SHA256SUMS`, SBOM and attestation bundle to a draft release.
  - `scripts/build-release.sh [--docker]` is the build both CI and anyone rebuilding a release use.
  - The verification procedure is in [docs/build-integrity.md](docs/build-integrity.md).
- **Live CT detection evaluation harness.**
  - `cybermesh ct watch` follows live static CT logs in one process, with verified checkpoints, consistency proofs and proven tile roots, and never skips a tile. It records every certificate name and every brand signal, with the log's timestamp and the time it was scanned. It is the single-server baseline for the cost of decentralisation, too.
  - `scripts/ct-eval.sh` runs it for a fixed window, takes hourly phishunt snapshots and resumes after a reboot.
  - The method, fixed before any results, is in [docs/ct-evaluation.md](docs/ct-evaluation.md).
- `cybermesh_ct::names::certificate_dns_names`: names with their wildcard flag (`certificate_names` is unchanged).
- `cybermesh ct evaluate` scores a run against confirmed phishing. It reports recall at three flag levels with Wilson intervals, lead time per source, a precision floor, a stratified false-alarm sample and a comparison with phishunt. `scripts/ct-eval.sh history` exports the OpenPhish git history as snapshots.
- `scripts/ct-cost.sh` measures the cost of decentralisation by scanning one fixed range of a live log in one process (`ct watch --end-tile`) and with a local network. The first results are in [docs/ct-evaluation.md](docs/ct-evaluation.md) §8.2: about 2.5× the download and 3.5× the CPU of one process (5.4× on a busier machine), with every task verified by two organisations.
- Coordinator and verifier reports and worker status now include `cpu_ms`, `ct_http_bytes` and `ct_http_requests`.

### Fixed
- Test harness: worker statuses were collected one at a time with a 10 s timeout, and a worker still stopping was silently left out. That made `full_pipeline_over_libp2p` fail on a slow CI runner. Now all workers are stopped first, every status is required, and a worker that does not stop fails the test with its name.
- **Review of `ct evaluate` before any result was computed:**
  - The phishunt comparison uses CyberMesh's log time, as pre-registered. Scan time is reported separately.
  - Each flag level keeps its own earliest time.
  - Downtime includes time before a log's first poll and after its last, clipped to the window.
  - Unreadable lines and truncated segments are counted instead of dropped or fatal.
  - Truncated feed snapshots drop their partial last line, and interrupted exports (`*.tmp`) are ignored.
  - Parser fixes: the `+00` zone, real month lengths, a scheme only at the start of a URL, the UTF-8 BOM.
  - New: `--rescore-evidence` re-assesses the stored names with a revised engine (§5), reading segments in parallel (`--threads`), and the "caught by CyberMesh only, phishunt only, both, neither" table.
  - Brands and codes are stored compactly.
- **`scripts/ct-cost.sh`:**
  - Every patch of the generated coordinator config is checked.
  - Workers are stopped cleanly, so their final figures are read.
  - The one-process side uses the same HTTP-level counters as the network.
- **`scripts/ct-eval.sh history`** fails loudly on a bad export and no longer fetches the unused phishunt mirror.
- `cybermesh ct report` counted a certificate twice for a brand named twice in one assessment.

## v0.3.0 (2026-11-18, research pre-release)

The wire protocol is unchanged, but the `ct-logs` evidence format is not compatible with v0.2.x: each log now needs `origin` and `public_key`. Nodes that run CT tasks must upgrade together and switch to a new evidence bundle. Deployments without a `ct-logs` source are unaffected. **Not production-ready; no external audit.**

### Added
- **CT follow mode** (`[ct] follow = true`). The coordinator tails a log as it grows:
  - it polls the checkpoint and accepts only a fresh, pinned-key-signed checkpoint that provably extends the previous one (an RFC 6962 consistency proof from the log's hash tiles);
  - it schedules newly completed tiles, with a per-poll cap and backlog limit;
  - it resumes after a restart from `ct-follow.json` (last signed head and a settled low-water mark);
  - it counts rewritten-history checkpoints (`ct_log_inconsistencies`) and does not follow them, halting after 3 in a row (`ct_follow_halted`; `coordinator run` then exits with an error);
  - only verified tiles advance the resume point, and given-up batches are retried;
  - `cybermesh ct follow-reset` clears the saved head while keeping the resume point.
- `TileAuthenticator::prove_extends`; `MockLog::extend` and `serve_shared`, so a mock log can grow while served; `cybermesh dev mock-ct-log --grow-tiles/--grow-every-secs/--max-tiles`. The local demo's coordinator now follows a growing mock log.
- **CT checkpoints are verified and tile roots are proven.**
  - `ct-logs` evidence now pins each log's `origin` and `public_key` (ECDSA P-256 SPKI). Real keys come from Google's CT log list v3.
  - The verifier accepts a checkpoint only with a valid RFC 6962 note signature by the pinned key.
  - It proves every tile root it relies on against the signed root, through hash tiles at all levels.
  - Hash tiles that contradict the signed checkpoint dispute the task without faulting anyone. A checkpoint that does not verify means no log access.
  - `ct checkpoint` and `ct scan` verify and prove too.
  - Validated against real Let's Encrypt and Google logs.
- `ct_checkpoint` fuzz target.

### Security
- Fixes from an internal review of checkpoint verification ([docs/security-review.md](docs/security-review.md), sixth pass):
  - tiles without a proven root leave the task `insufficient`, and their rescans are never evidence against workers;
  - stale (more than an hour old) or future-dated checkpoints are refused;
  - full-tile fallback for deleted partial tiles;
  - only a hash mismatch counts as a log contradiction;
  - malformed signature lines under the pinned name reject the note;
  - the demonstration key is refused outside loopback test logs.

### Changed
- `TileSource::hash_tile(level, …)` replaces `level1_tile`. The unauthenticated `tile_root` helper is removed (use `proof::TileAuthenticator`).
- The mock CT log signs its checkpoints with a fixed public demonstration key and serves hash tiles at every level.

## v0.2.2 (2026-11-17, research pre-release)

Wire-compatible with v0.2.x: nodes without record distribution ignore the new `records` topic. **Not production-ready; no external audit.**

### Added
- **Verification records are distributed over the network.**
  - Verifiers publish every record they sign on a new `records` gossip topic and store the others' in `received-records/`.
  - Received records are authenticated as release builders do. The store is bounded and deduplicated, and refuses future-dated, stale and own records. Recent records are re-published so briefly disconnected peers catch up.
  - Each organisation's release signer can now build from its own node alone: `--records state/records --records state/received-records`.
  - Both demos show it: release signers no longer read another organisation's state.
- `records_wait_secs`: with `exit_when_done` or `idle_exit`, a node waits (bounded) for the other verifiers' records of the tasks it settled.

### Changed
- `cybermesh release build` and the nodes share one record check (`cybermesh_verifier::verify_record_envelope`). `persist_record` returns the signed envelope as well.
- `cybermesh release build` skips, and names, record files that do not verify against the build-time manifest. `--strict` restores aborting on them.

### Security
- Fixes from an internal review of record distribution ([docs/security-review.md](docs/security-review.md), fifth pass):
  - byte and per-operator quotas;
  - normalised storage, so re-wrapped envelopes cannot inflate it;
  - pruning by age, and a re-check on every manifest update;
  - no penalties for non-provable failures;
  - a per-tick publish limit and a typed duplicate error;
  - re-publication after a restart.

## v0.2.1 (2026-11-17, research pre-release)

Demo changes only; wire-compatible with v0.2.0. **Not production-ready; no external audit.**

### Added
- The Docker Compose demo runs organisation B's independent verifier in its own hardened container, with only its own key and its own state. The manifest requires `min_verifiers = 2`, and the release containers show the quorum check: the coordinator's records alone publish nothing. Both signers then build from both verifiers' records.

### Changed
- `cybermesh demo init --independent-verifiers` defaults to 1 in both local and docker modes. Docker mode supports 0 or 1.

## v0.2.0 (2026-11-17, research pre-release)

**Not production-ready; no external audit.** v0.1.0 and v0.2.0 nodes cannot interoperate (wire-format changes below).

### Added
- `ct-shard-scan` task type: distributed Certificate Transparency monitoring of static CT API logs. It is opt-in per operator, reaches only pinned log endpoints, verifies against the logs' level-1 hash tiles with spot checks and confirm-before-publish, and produces an investigation report (`cybermesh ct report`). Publishing CT findings as warnings is opt-in and capped at `warn`.
- `cybermesh ct checkpoint|scan|report`, `cybermesh dev mock-ct-log`, and CT in the local demo.
- Persisted manifest state, so a restart cannot roll a node back to an older manifest.
- `ct_tile` fuzz target.
- Optional `min_sequence` in the governance root: a floor for manifest sequences, also for nodes without stored state.
- `cybermesh ct report` output now has a `coverage` section listing truncated and log-inconsistent tiles.

- **Independent verifiers** (`cybermesh verifier run`). Other organisations follow tasks and results, recompute with their own engine, evidence, CT log access and spot-check seed, and sign their own records. With the new manifest field `min_verifiers`, a release lists a domain only if that many distinct verifier operators agree, and `block` only if that many say `block`. `release build` takes one `--records` directory per verifier and checks each record's named verifier against its signer and the manifest. The local demo runs a verifier at organisation B with `min_verifiers = 2`.

### Changed
- `VerificationRecord` carries `verifier: {key, operator}` in its signed payload. `BuildParams` has `min_verifiers`.
- Coordinator `start_after_workers`: issue nothing until that many workers are live (fallback: `abandon_after`). The test harness and the demo wait for all their workers, which fixes flaky adversarial network tests in CI where the simulated adversary was never assigned a task.
- Engine 0.4.0: plain truncations of brand tokens are no longer lookalikes. This came from real CT false positives.
- Heartbeats carry `capabilities`, and verification records carry an optional `ct` section. This is a wire-format change: v0.1.0 nodes cannot interoperate with v0.2.0 nodes.
- `ENGINE_VERSION` now records the pinned `x509-parser` version (`0.4.0+psl.2.1.255+idna.1.1.0+x509.0.18.1`).

### Security
- Fixes from an internal review of the CT code ([docs/security-review.md](docs/security-review.md), third pass):
  - match caps chosen by risk;
  - results that always fit one message (16 tiles per task);
  - a names digest in every tile result;
  - two spot checks, one biased to tiles with matches;
  - CT scans and CT verification moved off the event loops;
  - stricter HTTP and log URL handling;
  - no faults when a log is itself inconsistent;
  - required `leaf_index`;
  - `x509-parser` pinned.
- Fixes from an internal review of the independent-verifier code ([docs/security-review.md](docs/security-review.md), fourth pass):
  - only recomputed records count towards a quorum of 2 or more;
  - bounded verifier state (followed tasks, early results by count, bytes and worker; settled tasks; accepted-only replay entries);
  - tasks keyed by digest against id squatting;
  - `release build` honours the governance root's `min_sequence`.

## v0.1.0 (research MVP)

First public version. **Not production-ready; no external audit.**

### Added
- Deterministic `DomainRiskAssessment` engine (lexical, brand, homograph and feed signals)
  with pinned evidence bundles and golden vectors.
- Versioned wire protocol over DSSE envelopes with canonical JSON, a governance-signed
  trust manifest, a replay cache and rate limiting.
- Permissioned libp2p gossipsub network: Noise, allowlist, manual validation,
  author-bound message ids, bounded queues.
- Worker runtime with a cooperative resource governor (CPU, memory, load, working hours,
  bandwidth, PAUSE/STOP controls), a hardened systemd unit and a Docker image.
- Coordinator that assigns tasks across distinct operators, recomputes results, detects
  faults (including late equivocation), quarantines workers and reassigns tasks.
- Deterministic, k-of-n distinct-operator co-signed releases with anti-rollback, appeals
  and corrections, and rollback.
- RFC 9162 transparency log, a local test chain and an OpenTimestamps adapter, all optional
  and off the protection path.
- Chromium MV3 browser extension with offline verification, advisory warnings, opt-in strict
  blocking and false-positive reporting.
- End-to-end, adversarial and performance tests over real libp2p; fuzz targets; CI with
  cargo-deny, gitleaks and SBOM.
- Temporal evaluation on public data and documentation (architecture, protocol, threat
  model, privacy, anchoring, evaluation, operator guide, roadmap).

### Release criteria for v0.1.0
- All CI gates green on `main`.
- Internal security review: all HIGH and MEDIUM findings fixed with regression tests.
- Evaluation published with its limitations.

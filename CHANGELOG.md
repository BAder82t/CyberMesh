# Changelog

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

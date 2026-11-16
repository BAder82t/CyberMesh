# Changelog

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

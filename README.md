# CyberMesh

**Community-verified phishing and malicious-domain intelligence that browsers can check offline.**

CyberMesh lets several independent organisations jointly produce a list of phishing and
malicious domains, and lets anyone verify that list without trusting a single provider. A
browser extension uses the signed list to warn people before they open a known phishing
site. It never sends their browsing history anywhere.

Concretely, in the current MVP:

- **Organisations run small workers.** A worker is an opt-in process capped at about 1 % of one CPU core. In our measurements a worker used 0.03–0.28 % CPU and 9–14 MiB of memory. Workers analyse domains with a deterministic, explainable engine and sign their results.
- **Results are checked, not voted on.** The verifier recomputes every result. A worker whose signed answer differs has provably misbehaved and is quarantined. Colluding workers cannot cause a block.
- **Releases are co-signed.** Two organisations rebuild each release independently and co-sign it only if they get byte-identical output. A single stolen signing key cannot publish a release.
- **Browsers verify offline.** The browser extension checks signatures against a pinned trust root and keeps protecting users from the cached list during an outage.
- **Anchoring is optional.** Release digests go into a Merkle transparency log, which can be anchored to a timestamping chain (local test chain or OpenTimestamps). Anchoring is never needed to enforce protection.

> **Status: research MVP (v0.1.0). Not production-ready.** The evaluation in [docs/evaluation.md](docs/evaluation.md) shows two things.
>
> 1. The *verification and distribution* design works as intended, including against adversarial workers.
> 2. The *lexical detection* adds only a few percent of early detection on phishing domains that feeds have not listed yet.
>
> For cheap lexical analysis, distributed computing gives **no** computational advantage over a single server. The report says so plainly and proposes a better use of donated computing capacity.

## What it protects against (and what it does not)

| Covered | Not covered |
|---|---|
| Visits to hosts listed in a verified release (feed-corroborated phishing/malware hosts, lexically suspicious lookalikes as advisory warnings) | Phishing pages on hosts not in the release; pages behind URL paths on legitimate hosts; attachments, SMS, voice |
| Forged, replayed or tampered tasks, results and releases | A majority of release-signing organisations colluding |
| Colluding or compromised workers trying to get benign domains blocked | Poisoned reference feeds that the verifier itself trusts (mitigated, not eliminated) |
| Network outages (cached, still-valid releases keep working offline) | Users who dismiss advisory warnings |

## Architecture at a glance

```mermaid
flowchart LR
  subgraph OrgB[Organisation B]
    WB1[Worker]:::w
    WB2[Worker]:::w
  end
  subgraph OrgC[Organisation C]
    WC[Worker]:::w
  end
  subgraph OrgA[Organisation A]
    C[Coordinator<br/>issuer + verifier]
    WA[Worker]:::w
    RA[Release signer A]
  end
  RB[Release signer B]
  C -- signed tasks (gossipsub) --> WA & WB1 & WB2 & WC
  WA & WB1 & WB2 & WC -- signed results --> C
  C -- signed verification records --> RA & RB
  RA & RB -- co-signed release --> CDN[(Static hosting)]
  CDN -- release.json --> EXT[Browser extension<br/>offline verification]
  RA -. digest .-> LOG[(Merkle log)] -. checkpoint .-> ANCHOR[(Local chain / OpenTimestamps)]
  classDef w fill:#eef,stroke:#88a
```

Details: [docs/architecture.md](docs/architecture.md) · protocol: [docs/protocol.md](docs/protocol.md) · threat model: [docs/threat-model.md](docs/threat-model.md) · privacy: [docs/privacy.md](docs/privacy.md) · anchoring: [docs/blockchain.md](docs/blockchain.md)

## Quick start

Requirements: Rust 1.98.1 (pinned via `rust-toolchain.toml`), Python 3 (helper scripts), and optionally Docker and Node 22 (browser extension).

```bash
# Build and run every test (unit, property, real-libp2p integration and adversarial)
cargo test --workspace --all-features

# Full local demonstration as separate processes on 127.0.0.1:
#  5 organisations, 6 workers (one simulated compromised), coordinator, release
#  co-signing, offline verification, transparency log and local-chain anchoring.
scripts/demo-local.sh --keep-serving

# The same demonstration with Docker Compose (hardened, cgroup-limited containers)
deploy/docker/demo.sh up
deploy/docker/demo.sh down
```

Then load the browser extension (see [apps/browser-extension/README.md](apps/browser-extension/README.md)) and open
`http://examplebank-secure-login.phish.localhost:8088/` — a locally served, clearly labelled
test page for a fictional bank — to see the warning. A step-by-step walkthrough is in
[docs/demo.md](docs/demo.md).

## Repository layout

| Path | Purpose |
|---|---|
| `crates/cybermesh-crypto` | Ed25519 identities, DSSE envelopes, strict canonical JSON, digests |
| `crates/cybermesh-protocol` | Versioned wire messages, governance-signed trust manifest, validation, replay cache, rate limiter |
| `crates/cybermesh-analysis` | Deterministic `DomainRiskAssessment` engine, evidence bundles, evaluation metrics |
| `crates/cybermesh-verifier` | Result binding, recomputation, conflict and fault detection, classification policy, reputation |
| `crates/cybermesh-intelligence` | Deterministic, multi-signed releases; appeals and corrections; rollback; offline verification |
| `crates/cybermesh-anchor` | RFC 9162 Merkle log and proofs, anchoring trait, local test chain, OpenTimestamps codec/client |
| `crates/cybermesh-network` | Permissioned libp2p gossipsub transport (Noise, allowlist, rate limits, bounded queues) |
| `crates/cybermesh-node` | Worker runtime with resource governor; coordinator runtime |
| `apps/cybermesh-cli` | `cybermesh` command-line tool |
| `apps/browser-extension` | Chromium MV3 extension (offline verification, warnings, strict mode) |
| `tests/` | End-to-end, adversarial and performance tests over real libp2p |
| `datasets/demo` | Demo evidence (synthetic feed, Majestic top-10k subset, brand table, hosting platforms) |
| `deploy/` | Dockerfile, Compose demo, hardened systemd unit |
| `docs/` | Architecture, protocol, threat model, privacy, anchoring, evaluation, operator guide, roadmap |

The proposed `cybermesh-core`, `cybermesh-consensus`, `cybermesh-reputation`, `cybermesh-worker` and dashboard packages were deliberately
not created as separate crates; see [docs/architecture.md](docs/architecture.md#crate-boundaries).

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Three independent internal
reviews (two security passes and one correctness review) were performed and their findings fixed; they are summarised in
[docs/security-review.md](docs/security-review.md). No external audit has been performed.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE). Demo data licences are listed in
[datasets/demo/evidence/NOTICE.md](datasets/demo/evidence/NOTICE.md).

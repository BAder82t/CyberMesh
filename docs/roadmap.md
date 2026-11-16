# Roadmap

The versions below are intentions, not commitments. Priorities follow the evaluation: the
verification and distribution layer works, while detection quality and the value of distributed
compute are the weak points.

## v0.1.0 (this release): research MVP
Deterministic engine, permissioned libp2p network, recomputation-based verification,
co-signed offline-verifiable releases, browser extension, Merkle log with local and
OpenTimestamps anchoring, Docker and local demos, internal security review, evaluation.

## v0.2: harden the pilot
- **Multiple verifiers.** Run verifiers at two or more organisations, require records from at least two verifiers for `block`, and persist manifest state, detecting manifest equivocation.
- **Runtime manifest reload.** Drop revoked peers from the allowlist without a restart.
- **Network.** Enable gossipsub peer scoring (invalid-message penalties), plus `/dns4` bootstrap and Kademlia discovery for more than 20 nodes.
- **Witnessed transparency log.** Organisations co-sign log checkpoints using the C2SP `tlog-checkpoint` and `tlog-cosignature` formats. Consistency is checked before co-signing.
- **Build integrity.** Signed, reproducible binary releases with attestations (SLSA provenance) and a published verification procedure.
- **Test OpenTimestamps compatibility** against the reference `ots` client and the public calendars, which is a manual and opt-in step.
- **Windows.** Run the worker as a service with Job Object limits. Add macOS `launchd` packaging.
- **Licensing.** Resolve the licensing question for feed-derived `block` entries (see `existing-work-review.md` §9). Prefer feeds whose licences permit redistribution of derived blocklists, or organisation-contributed, analyst-confirmed reports under a CyberMesh data licence.

## v0.3: a task type where donated compute matters
The evaluation shows that lexical analysis runs at about 37,000–52,000 domains per second on one core, so a single server does it easily. The candidate workload that *does* benefit from many independent, resource-limited contributors:

- **Certificate Transparency lookalike monitoring (`CtShardScan`).**
  - Each task assigns a range of a public CT log, a few million entries.
  - Workers stream the range from the log's public API and match subject names against the protected-brand table and confusables.
  - The output is newly issued certificates for lookalike names, often hours before a phishing site goes live.
  - *Public data only*, no contact with suspicious hosts, and it is bandwidth- and CPU-heavy enough that distribution helps.
  - Verification cannot recompute everything cheaply, so it uses **sampled re-execution** by a second independent operator plus Merkle commitments over the scanned range (the CT tree head proves range coverage).
- **Multi-vantage DNS observation**, as an approved, rate-limited, resolver-only signal. It is useful for detecting fast-flux and geo-targeted resolution, but needs a careful safety review first.

## v0.4 and later
- **Detection.** Add a learned lexical model shipped as pinned evidence, deterministic integer inference, and trained only on licensed data.
- **Releases.** Add delta releases and hashed-indicator releases (k-anonymity buckets) for very large lists.
- **Appeals.** Add a public appeal-tracking site and governance tooling, and a stated service level for appeals.
- **Dependencies.** Replace dependencies flagged by `cargo-deny`, for example `paste` through libp2p.

# Roadmap

The versions below are intentions, not commitments. Priorities follow the evaluation: the
verification and distribution layer works, while detection quality and the value of distributed
compute are the weak points.

## v0.1.0: research MVP
Deterministic engine, permissioned libp2p network, recomputation-based verification,
co-signed offline-verifiable releases, browser extension, Merkle log with local and
OpenTimestamps anchoring, Docker and local demos, internal security review, evaluation.

## v0.2.0: CT monitoring and independent verifiers
- **Certificate Transparency monitoring.** The `ct-shard-scan` task type:
  - verification against the logs' own hash tiles, with spot checks and confirm-before-publish;
  - an investigation report.

  See [ct-monitoring.md](ct-monitoring.md).
- **Multiple verifiers.**
  - independent verifier nodes (`cybermesh verifier run`);
  - records that name their verifier;
  - a governance-set `min_verifiers` release quorum (listing and `block` both need it).
- **Manifest state.** Nodes persist the highest manifest sequence, and the governance root can set a `min_sequence` floor. Runtime reload with live revocation shipped in v0.1.0.

## v0.2.1: independent verifier in the Docker demo
The Docker Compose demo runs organisation B's independent verifier in its own hardened container, with `min_verifiers = 2`, matching the local demo. It is wire-compatible with v0.2.0.

## v0.2.2: verification records over the network
Verifiers publish the records they sign on a `records` gossip topic and store the others' records. Each organisation's release signer builds from its own node alone. It is wire-compatible with v0.2.x: older nodes ignore the topic.

## v0.3.0: authenticated CT logs and continuous tailing
- **Checkpoint verification.** Each log's checkpoint must be signed by the key pinned in the `ct-logs` evidence and be fresh. Every tile root the verifier relies on is proven against the signed root.
- **Follow mode.** The coordinator follows a log as it grows. It accepts a new checkpoint only with a consistency proof that it extends the previous one, and it resumes after a restart without skipping tiles.

The wire protocol is unchanged, but the `ct-logs` evidence format is not compatible with v0.2.x. Nodes that run CT tasks must upgrade together; see the changelog.

## v0.3.1: evaluation tooling and verifiable binaries
- **Live CT evaluation.** `cybermesh ct watch` records every certificate name and brand signal of live logs. `cybermesh ct evaluate` scores a run against independently confirmed phishing, following a method fixed before any results ([ct-evaluation.md](ct-evaluation.md)). A week-long run is in progress.
- **Cost of decentralisation.** `scripts/ct-cost.sh` measured about 2.5× the download and 3.5× the CPU of a single process, with every task verified by two organisations.
- **Build integrity.** Release binaries are built twice and must match. They carry SLSA Build Level 2 provenance and can be rebuilt bit for bit on Linux ([build-integrity.md](build-integrity.md)).

It is compatible with v0.3.0.

## v0.3.2: ready for a pilot
- **Pilot kit.** An invitation for organisations ([pilot.md](pilot.md)), a page for their security teams on what a node exposes them to ([node-risk.md](node-risk.md)), and a hardened systemd unit for independent verifiers. The operator guide now installs from a verified release.
- **Host names in peer addresses** (`/dns4/...`). The peer id in the address is authenticated, so a spoofed DNS answer can only make a connection fail.
- **CT evaluation.** Revision 1 is frozen before the test window. The dev-window results are published ([ct-evaluation.md](ct-evaluation.md) §5.1, §8.1).

It is compatible with v0.3.x.

## v0.3.3: organisations witness CT logs
- **CT log witnessing.** Verifiers cosign log checkpoints (C2SP `cosignature/v1`) and compare their views. A log that shows different organisations different trees is proven with a proof anyone can check offline, and is no longer relied on ([ct-monitoring.md](ct-monitoring.md) §3, threat model T28).
- **Brand list from CT data.** `cybermesh evidence suggest-owned-domains` finds brand owners' own domains. The shipped list adds 13 of them: 73.5 % fewer warn-level names on the evaluation's dev window, with no detection lost.

It is compatible with v0.3.x.

## v0.3.4: consequences for misbehaviour
- **Penalty-only peer scoring.** A provably invalid message counts against its author, never against relays. About three within ten minutes graylist the author, and nothing an honest node can produce is charged (threat model T29).
- **The coordinator acts on faults proven by other verifiers.** An independent verifier that proves a worker misbehaved publishes a fault proof with the signed task and the worker's own signed results. The coordinator re-checks it before quarantining the worker: offline for equivocation and mismatched results, by its own recomputation or CT re-scan otherwise. Unconfirmed claims change nothing. Two results from one worker are equivocation only if they assert different things.
- **Ownership.** CyberMesh is copyright VaultBytes Innovations Ltd (`NOTICE`); the licence remains Apache-2.0.


## v0.3.5: classic CT logs, and verifiers that prove late equivocation
- **Classic RFC 6962 CT logs.** Workers, verifiers, the coordinator (also following) and the CLI use them, selected by `api` in the `ct-logs` evidence. The 17 usable logs of DigiCert, Cloudflare, Sectigo and TrustAsia are listed in `datasets/ct-logs/public-rfc6962-ct-logs.json` and were checked against the live logs ([ct-monitoring.md](ct-monitoring.md) §8).
- **Independent verifiers prove late equivocation.** A verifier keeps the evidence of settled tasks and publishes a fault proof when an accepted worker later contradicts itself (threat model T30).
- **README.** The opening describes the resilience-network vision, with the current implementation stated separately.

It is compatible with v0.3.x. Evidence without `api` and its pins are unchanged.


## v0.3.6 (this release): classic logs, checked against real ones
- **Following two real classic logs for ten minutes** (DigiCert Wyvern and Cloudflare Nimbus) found two faults in v0.3.5, both fixed:
  - Downloaded bytes counted only a third of what a classic log sends (its `get-entries` answer also carries certificate chains), so a worker's bandwidth cap paced it about three times too fast. Real classic logs cost about 6 KiB per entry against about 1.5 KiB for a static log ([ct-monitoring.md](ct-monitoring.md) §8).
  - A tree head more than an hour old was refused for every log, but classic logs may sign one only once per 24 hours: Nimbus went more than an hour between heads. The limit is now chosen by the log's API (an hour for static logs, 24 hours for classic ones).
- **Dependencies.** `url` is updated for RUSTSEC-2026-0592.

It is compatible with v0.3.x. No evidence format change.

## Evaluation milestone: CT detection results (from 2026-11-28)
The week-long live run's CT window ends on 2026-11-25, and its feed snapshots on 2026-11-28. Then the test window (days 3–7) is scored for both engines, as shipped and with the frozen revision 1, following the method fixed in advance. The results are published in [ct-evaluation.md](ct-evaluation.md) §8.1, failures included.

## Next: harden the pilot
- **CT.**
  - Exchange checkpoint cosignatures with external witness networks (C2SP `tlog-witness`), and consider ML-DSA-44 cosignatures. Witnessing between CyberMesh verifiers is done: they cosign checkpoints, compare their views and prove split views ([ct-monitoring.md](ct-monitoring.md) §3).
  - RFC 6962 logs are supported: workers, verifiers, the coordinator (also following) and the CLI use them, selected by `api` in the `ct-logs` evidence ([ct-monitoring.md](ct-monitoring.md) §8). The 17 usable classic logs are listed in `datasets/ct-logs/public-rfc6962-ct-logs.json` and were checked against the live logs. Still to do: measure their cost and decide which to follow in the evaluation.
  - Brand infrastructure lists confirmed by the brand owners, needed before CT warnings can be enabled widely. `cybermesh evidence suggest-owned-domains` already proposes candidates from CT data.
- **Operators.** `cybermesh doctor` checks a node's configuration before it joins (done). Still to do: a warning in the node's own log days before the manifest expires, and a disk-space check.
- **Network.** Kademlia discovery for more than 20 nodes. (Host names in peer addresses and penalty-only gossipsub peer scoring are done.)
- **Witnessed transparency log.** Organisations co-sign log checkpoints using the C2SP `tlog-checkpoint` and `tlog-cosignature` formats. Consistency is checked before co-signing.
- **Build integrity.** Reproducible release binaries (checked by building every target twice), SLSA Build Level 2 provenance attestations and a published verification procedure are in place: see [build-integrity.md](build-integrity.md). Still to do: SLSA Build Level 3 (an isolated reusable workflow), Apple notarisation, Windows binaries.
- **OpenTimestamps compatibility.** Done for pending proofs in both directions against the reference `ots` client and the public calendars ([blockchain.md](blockchain.md) §2.2). Still to do: upgrade a proof to its Bitcoin attestation and check it against a node.
- **Windows.** Run the worker as a service with Job Object limits. (macOS `launchd` daemons are done: `deploy/launchd/`.)
- **Licensing.** Resolve the licensing question for feed-derived `block` entries (see `existing-work-review.md` §9). Prefer feeds whose licences permit redistribution of derived blocklists, or organisation-contributed, analyst-confirmed reports under a CyberMesh data licence.

## Original v0.3 plan: a task type where donated compute matters
*Certificate Transparency monitoring from this plan shipped in v0.2.0. It verifies against the logs' own hash tiles and spot checks rather than full re-execution; see [ct-monitoring.md](ct-monitoring.md).*

The evaluation shows that lexical analysis runs at about 37,000–52,000 domains per second on one core, so a single server does it easily. The candidate workload that *does* benefit from many independent, resource-limited contributors:

- **Certificate Transparency lookalike monitoring (`CtShardScan`).**
  - Each task assigns a range of a public CT log, a few million entries.
  - Workers stream the range from the log's public API and match subject names against the protected-brand table and confusables.
  - The output is newly issued certificates for lookalike names, often hours before a phishing site goes live.
  - *Public data only*, no contact with suspicious hosts, and it is bandwidth- and CPU-heavy enough that distribution helps.
  - Verification cannot recompute everything cheaply, so it uses **sampled re-execution** by a second independent operator plus Merkle commitments over the scanned range (the CT tree head proves range coverage).
- **Multi-vantage DNS observation**, as an approved, rate-limited, resolver-only signal. It is useful for detecting fast-flux and geo-targeted resolution, but needs a careful safety review first.

## Exploration: a continuity runtime (separate track)
A separate idea, kept apart from CyberMesh releases: organisation-managed devices keep essential business workflows running when a central server or cloud is unavailable. CyberMesh's trust layer would carry over:
- governance-signed membership and revocation;
- authenticated, allowlisted peer-to-peer networking;
- threshold-signed manifests as signed workloads;
- the resource governor.

Replicated application state and reconciliation are the hard part.

After the CT evaluation, a two-week feasibility spike will test the central question: can a small stateful workflow survive the loss of its central server on ordinary managed devices, without losing or duplicating operations?
- **Setup.** Five devices on a LAN, an offline-capable order and task application, durable local queues, and CyberMesh membership and manifests for device enrolment and signed workloads.
- **Measures.** Recovery time, operations lost or duplicated (none allowed), reconciliation correctness and resource use.
- **Order.** Low-risk workflows (retail, warehouses) before regulated ones.
- **Later phases: more kinds of device.** If the first phase works, a Raspberry Pi joins as an always-on edge node, then browsers and phones as light clients.
  - Every compatible device can take part, but not every device does the same job. Roles follow each device's measured capability and trust, and only approved, stable nodes hold application state.
  - Phones and browser tabs participate only while active: iOS and Android limit background work, and a tab is not a server.
  - Browsers and phones would need WebRTC or WebSocket transports and native apps, a separate effort.

  None of this changes the structure of the CyberMesh repository.

## v0.4 and later
- **Detection.** Add a learned lexical model shipped as pinned evidence, deterministic integer inference, and trained only on licensed data.
- **Releases.** Add delta releases and hashed-indicator releases (k-anonymity buckets) for very large lists.
- **Appeals.** Add a public appeal-tracking site and governance tooling, and a stated service level for appeals.
- **Dependencies.** `paste` (unmaintained, a compile-time macro on Linux only) is gone from the build: `if-watch` is vendored in `vendor/if-watch/` on the netlink 0.9 crates, which do not need it (the same change as `if-watch` PR #55, which is not yet reviewed or released). Remove the vendored copy when `if-watch` releases on that line ([VENDORED.md](../vendor/if-watch/VENDORED.md)). Tested on Linux x86_64 on 2026-11-22/23.

# CyberMesh pilot: an invitation to participating organisations

CyberMesh is a community-run cyber-defence network:
- organisations contribute a little spare computing capacity;
- the network analyses public security signals;
- independent organisations verify each other's work;
- the result is signed protection that no single commercial provider controls.

Its current applications flag phishing and lookalike domains: in newly registered names, and in every new certificate published in Certificate Transparency logs.

The software works end to end in tests and demonstrations, but so far every node has been run by one party. This pilot is the step that matters next: **independent organisations operating real nodes for a few weeks**, so we can measure whether the network finds threats earlier or better than existing services, and at what cost to participants.

## What we want to learn

- Whether organisations other than the maintainers can run nodes with little effort, and what gets in the way.
- How early CyberMesh flags phishing domains compared with independent confirmation by OpenPhish, Google Safe Browsing and PhishTank, and compared with an existing CT-based detector. The method is fixed in advance ([ct-evaluation.md](ct-evaluation.md)).
- What decentralising the work costs each participant, measured, not estimated. A first local measurement is in [ct-evaluation.md](ct-evaluation.md) §8.2.

**Success:**
- at least **3 independent organisations**;
- **10–20 workers** in total;
- a **7-day** measurement run;
- a published evaluation that includes the failures and limitations.

## What you would run

Pick one or both roles:

| Role | What it does | Typical effort |
|---|---|---|
| **Worker** | Analyses public domain names, and optionally CT log tiles, from signed tasks, and signs its results. | One small Linux VM or an existing server. Setup about 1 hour, then near-zero operation. |
| **Independent verifier** | Recomputes the network's tasks and signs its own verification records. With a verifier and a release-signing key, your organisation co-signs what the network publishes. | As a worker, plus someone to look at disputes. |

Resources each worker uses (all are limits you set, and the systemd unit enforces hard caps):

| | Worker | Independent verifier |
|---|---|---|
| CPU | 1 % of one core on average (hard cap 2 %) | Small on average, in bursts (hard cap 25 %) |
| Memory | up to 200 MB | up to 512 MB |
| Network | 64 KiB/s outbound. With CT scanning, up to 256 KiB/s of downloads from public CT logs. | Low. CT spot checks download about a fifth of a scanner's volume. |
| Disk | Tens of MB | About 3–8 KB per verified task, for its own and the other verifiers' records. Following three CT logs (about 32,000 tasks a day) that is a few hundred MB a day; received records are pruned after 30 days. |
| Inbound port | Optional | One TCP port |
| Platform | Linux x86-64 or arm64 with glibc 2.34 or later (Debian 12, Ubuntu 22.04, RHEL 9 or newer) | Same |

Your security team will want [node-risk.md](node-risk.md). That one page covers exactly what a node contacts, holds and can be made to do, and how to switch it off.

## How it works for you

1. **Agree to take part** and name a technical contact and a security contact.
2. **Install a verified release.** Check the binary's checksum and its signed build provenance before installing ([build-integrity.md](build-integrity.md)).
3. **Generate a key on your host.** Only the public key goes to the network's governance group.
4. **Receive the signed network manifest**, the trust root and the evidence bundle, and start the node with the hardened systemd unit.

   [operator-guide.md](operator-guide.md) has each command.
5. **During the pilot** your node needs no attention. You can pause or stop it at any time.
6. **At the end** your member is removed from the manifest, and you delete the key and the state directory.

## What you get

- Early, signed and independently verified warnings about lookalike domains of the brands the network protects. The brand list is part of the network's evidence, so your own brands can be added to it, and the CT investigation report then covers them.
- A share in governance, if you want one. The network's manifest is signed by a threshold of governance keys, and participating organisations can hold one.
- Credit in the published evaluation, or anonymity if you prefer.
- The evaluation itself: lead time, recall, false alarms and cost, failures included.

## What we ask you to accept

- This is research software. It has had internal security reviews but **no external audit**, and it is not production-ready. Run it on a host you are comfortable isolating.
- Your node's IP address is visible to the other participants, and to public CT log operators if you enable CT scanning.
- The pilot measures, and does not promise, protection. The current lexical engine catches only a small share of unseen phishing domains ([evaluation.md](evaluation.md)). Finding out whether certificate monitoring does better is part of the point.

## Timeline

| Week | |
|---|---|
| 0 | Enrolment: keys, manifest, installation |
| 1 | Test run: the nodes join, and the first tasks and verification records come in |
| 2 | 7-day measurement run |
| 3 | Analysis and draft write-up, shared with participants first |

## Getting in touch

Open an issue on the project repository to express interest, or ask the maintainers directly. Report security problems privately, as described in [SECURITY.md](../SECURITY.md).

# What running a CyberMesh node exposes you to

This page is for the security team of an organisation asked to run a CyberMesh worker or an independent verifier. It states what a node contacts, what it holds, what other participants can make it do, and how to stop it. Each claim points to the code, test or document behind it.

CyberMesh is a research project (v0.3.6). It has had internal security reviews but **no external audit**. A pilot should run on a machine you would be comfortable isolating.

## At a glance

| Question | Worker | Independent verifier |
|---|---|---|
| Runs code, scripts or URLs sent by others? | No | No |
| Contacts the domains it analyses? | No: it analyses *names* only | No |
| Outbound connections | Enrolled peers (TCP, libp2p). CT log hosts over HTTPS only if you enable CT scanning. | Enrolled peers. The pinned CT log hosts, for spot checks and, if you enable `[ct_witness]`, checkpoint polls. |
| Inbound connections | Optional: one TCP port if peers should dial you | One TCP port, usually, so workers and the coordinator reach you directly |
| Accepts connections from | Enrolled peers only (allowlist from the signed manifest) | Same |
| Data it handles | Public domain names and certificate names; scores; signatures | The same, plus everyone's results for the tasks it verifies |
| Your internal data | Never read | Never read |
| Privileges | Unprivileged user, no capabilities, read-only system, system-call filter | Same |
| CPU | 1 % of one core on average (its own limit); 2 % hard cap (systemd) | Bursty, small on average; 25 % hard cap (systemd) |
| Memory | 200 MB (its own limit and hard cap) | 512 MB hard cap |
| Network volume | 64 KiB/s outbound. CT scanning adds downloads of up to 256 KiB/s. | Low. CT spot checks download about a fifth of what one scanner does. |
| Secrets on the host | One Ed25519 signing key | One Ed25519 signing key, and optionally your organisation's release-signing key |
| Off switch | `cybermesh worker stop` or `systemctl stop` | `systemctl stop` |

## Network

**Peers.** A node connects only to peers whose keys are in the network's manifest, which a threshold of governance keys signs.
- Connections from other peers are refused, and the allowlist is updated when the manifest changes. A revoked peer is disconnected within about a minute.
- A node keeps at most 2 connections per peer and 128 in total.
- Messages larger than 256 KiB are dropped, and each peer is rate-limited.

Code: `crates/cybermesh-network/src/node.rs`. Tests: `revoked_peer_is_disconnected_and_ignored`, `oversized_and_malformed_inputs_are_rejected`.

**Inbound.** A worker does not need to accept connections. It can dial the coordinator and other peers itself. If you open a port, open only that one, which is the `listen` address in its configuration (default examples: 4100 for a worker, 4200 for a verifier).

**CT logs** (only if you enable `ct_scanning`, and for verifiers).
- The node downloads public certificate-log tiles over HTTPS from the log URLs pinned in the network's evidence bundle.
- Requests go only to fixed paths derived from tile numbers. They follow no redirects and have size caps and timeouts.
- Nothing in a task can name another host. A task names a log id that must already be in your local evidence.

Code: `crates/cybermesh-ct/src/http.rs`. A firewall rule allowing outbound HTTPS only to those log hosts is a reasonable extra control. Each log's host is in `ct-logs.json` in the evidence bundle.

**DNS.** A node resolves only two kinds of host name, both through the system resolver, and never the domains it analyses:
- peer host names written in its own configuration (`/dns4/...` bootstrap addresses);
- the pinned CT log hosts, when it scans or witnesses CT.

A spoofed answer for a peer's name can only make that connection fail: the address names the peer id, which the encrypted handshake authenticates (threat model T27).

**Nothing else.** A node has no update channel, no telemetry and no other outbound traffic. The optional OpenTimestamps anchoring is run by a release signer on demand, not by nodes.

## What a participant could do to your node

| A participant who is... | ...can | ...cannot |
|---|---|---|
| any enrolled peer, including a compromised one | see your node's IP address and how it participates; send messages, which are rejected unless correctly signed and within limits; use up its rate allowance. A peer that sends provably invalid messages is graylisted: your node then ignores everything it sends for a while (`net_penalised_peers` in the reports) | make your node run code, fetch arbitrary URLs, read files outside its state directory, or exceed its resource limits |
| the coordinator (the task issuer), if compromised | send your worker tasks to analyse: lists of domain names, or tile ranges of a pinned CT log; see your results | change your local evidence or trust root, make your node contact the domains, or forge another organisation's results or releases (threat model T4) |
| another verifier | see your verifier's records, which are public by design; send it cosigned CT log checkpoints, which it compares with its own view (a few hash-tile downloads per peer and minute); send the coordinator proofs of faults, which it re-checks (a few re-scans at most at a time) | make your verifier sign anything it did not recompute itself; make it believe a log misbehaved (a split view is proven only by two checkpoints the log itself signed); or get your worker quarantined without a fault the coordinator confirms itself |

Malformed input is the usual way into network software. The parsers for tasks, envelopes, releases, OpenTimestamps proofs, domains, CT checkpoints and CT tiles are fuzzed (`fuzz/`), and the protocol uses canonical encodings and signature domain separation (`docs/protocol.md`).

## On the host

- **Sandbox.** The units in `deploy/systemd/` run the node as an unprivileged user:
  - no capabilities, and `NoNewPrivileges`;
  - read-only access to the system and `/etc/cybermesh`, with write access only to its own state directory;
  - no home directories and private `/tmp`;
  - a system-call filter, and `MemoryDenyWriteExecute`;
  - hard CPU and memory limits.

  `systemd-analyze security` rates both units at an exposure level of 1.1 ("OK") on its 0–10 scale.
- **Its own limits.** The worker also enforces its CPU, memory and bandwidth budget itself. It pauses while the machine is busy (load per CPU above 0.8) or outside the hours you allow (`active_hours_utc`).
- **Keys.** The signing key is generated on the host and never leaves it; you send governance only the public key. If you suspect the key is compromised:
  1. stop the node;
  2. ask governance to revoke the key;
  3. re-enrol with a new key.

  Other nodes re-read their manifest every 60 seconds, so a stolen key is useful until the revoking manifest reaches them (threat model T3).
- **Data at rest.**
  - A worker keeps a status file and, if you enable them, logs.
  - A verifier keeps the signed verification records it produced and received. These cover public domain names and pseudonymous worker keys, and are intended to be published.
  - No user data is ever stored (`docs/privacy.md`).

## What we ask you to accept

- **Your IP address is visible** to the other participants of a permissioned network, and to CT log operators if you scan CT. The network is not anonymous.
- **Research software.** It has had no external audit, and the [security review](security-review.md) lists what has been tested. Run it on a host you can isolate, and install only verified binaries (`docs/build-integrity.md`).
- **Denial of service by a peer within its rate allowance** is out of scope for the MVP (`SECURITY.md`). The resource limits bound the effect on your host.

## Stopping and leaving

```bash
cybermesh worker pause --control-dir /var/lib/cybermesh/control   # stop taking tasks, stay connected
cybermesh worker stop  --control-dir /var/lib/cybermesh/control   # exit within about 250 ms
sudo systemctl disable --now cybermesh-worker                      # or cybermesh-verifier
```

To leave, ask governance to remove your member from the next manifest, then delete the key and the state directory. Nothing is left behind elsewhere: other participants keep only the signed records your node published.

## Reporting a problem

Report security problems privately through GitHub's vulnerability reporting, as described in [SECURITY.md](../SECURITY.md), not as public issues.

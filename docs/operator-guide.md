# Operator guide: enrolling an organisation-controlled worker

This guide is for an organisation that wants to contribute a worker to a CyberMesh network.
Participation is opt-in and can be paused or stopped at any time.

Before you start, your security team may want [node-risk.md](node-risk.md): what a node contacts,
holds and can be made to do. For the pilot itself, see [pilot.md](pilot.md).

## 1. What a worker does and does not do

| Does | Does not |
|---|---|
| Connects to enrolled peers only (allowlist from the governance-signed manifest) | Accept connections from unknown peers |
| Accepts signed `domain-risk-assessment` tasks from the enrolled issuer | Run code, scripts, URLs or commands from the network |
| Analyses domain *names* against locally pinned public evidence | Fetch, resolve or contact the domains it analyses |
| Signs and publishes its results; sends heartbeats | Read browser histories, documents, credentials or security logs |
| Stays within the CPU, memory, bandwidth and working-hour limits you set | Act as a proxy, crawler or scanner |

## 2. Enrolment procedure

0. **Install a verified binary.** Download the binary for your platform and `SHA256SUMS` from
   the [latest release](https://github.com/BAder82t/CyberMesh/releases), then check the checksum
   and the signed build provenance before installing it
   ([build-integrity.md](build-integrity.md)):
   ```bash
   V=0.3.3 T=x86_64-unknown-linux-gnu        # or aarch64-unknown-linux-gnu
   sha256sum --ignore-missing -c SHA256SUMS
   gh attestation verify "cybermesh-$V-$T" --repo BAder82t/CyberMesh \
     --signer-workflow BAder82t/CyberMesh/.github/workflows/release.yml
   sudo install -m 0755 "cybermesh-$V-$T" /usr/local/bin/cybermesh
   cybermesh --version
   ```
   The binaries need glibc 2.34 or later: Debian 12, Ubuntu 22.04, RHEL 9 or newer.
   `gh attestation verify` needs the GitHub CLI, on any machine. You can also rebuild the
   binary yourself and compare its hash.
1. **Generate keys on the worker host.** Private keys never leave the host.
   ```bash
   sudo useradd --system --home /var/lib/cybermesh --shell /usr/sbin/nologin cybermesh
   sudo install -d -o cybermesh -m 700 /etc/cybermesh/keys
   sudo -u cybermesh cybermesh keygen --out /etc/cybermesh/keys/worker.key.json
   sudo -u cybermesh cybermesh key-info --key /etc/cybermesh/keys/worker.key.json
   ```
2. **Submit an enrolment request** to the network's governance group. It contains:
   - your organisation name and the requested operator id (`[a-z0-9-]`, 2–32 characters);
   - the worker's **public key** from `key-info` (never the key file);
   - the worker's reachable address, if it should accept inbound peer connections;
   - a security contact.
3. **Governance adds the member and re-signs the manifest.** A threshold of governance keys signs the new manifest with an increased sequence number:
   ```bash
   cybermesh governance sign-manifest --manifest manifest.unsigned.json --key gov-1.key.json --out manifest.json
   cybermesh governance sign-manifest --manifest manifest.unsigned.json --key gov-2.key.json --merge manifest.json --out manifest.json
   ```
4. **Install the trust material** on the worker:
   - `governance-root.json`, the pinned trust anchor, obtained **out of band**, for example from the governance group's signed announcement. Its optional `min_sequence` is the lowest manifest sequence the node accepts. Nodes also store the highest sequence they have accepted in `manifest-state.json` in their state directory, so a restart cannot roll them back;
   - `manifest.json`;
   - the evidence bundle directory. Its digests must match what tasks pin, so check it with `cybermesh evidence verify --dir ...`.
5. **Configure** `/etc/cybermesh/worker.toml`. The demo's `worker-*.toml` files are complete examples.
   ```toml
   network_id = "cybermesh-pilot"
   key = "/etc/cybermesh/keys/worker.key.json"
   manifest = "/etc/cybermesh/manifest.json"
   governance_root = "/etc/cybermesh/governance-root.json"
   evidence_dir = "/etc/cybermesh/evidence"
   state_dir = "/var/lib/cybermesh"
   control_dir = "/var/lib/cybermesh/control"
   listen = ["/ip4/0.0.0.0/tcp/4100"]
   bootstrap = ["/dns4/coordinator.example.org/tcp/4100/p2p/12D3KooW..."]  # or /ip4/...
   heartbeat_secs = 10

   [resources]
   cpu_percent = 1.0            # average CPU ceiling (percent of one core)
   cpu_window_secs = 60         # averaging window and maximum burst credit
   memory_mb = 200              # pause new work above this resident size
   max_load_per_cpu = 0.8       # pause while the machine is busy
   outbound_kib_per_sec = 64    # outbound application bandwidth
   max_queue = 16
   active_hours_utc = ["18:00-07:00"]  # e.g. outside office hours
   ```
   *Note:* bootstrap addresses can name a peer by host name (`/dns4/`, `/dns6/` or `/dns/`), resolved with the system resolver, or by IP (`/ip4/`, `/ip6/`). Always include the `/p2p/<peer id>` part: it is what authenticates the peer, so a wrong DNS answer can only make the connection fail.
6. **Run under the hardened systemd unit** in [`deploy/systemd/cybermesh-worker.service`](../deploy/systemd/cybermesh-worker.service). It adds OS-enforced limits: `CPUQuota=2%`, `MemoryMax=200M`, a read-only system, no capabilities, and a system-call filter.
   ```bash
   sudo cp deploy/systemd/cybermesh-worker.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now cybermesh-worker
   ```

## 2a. Optional: Certificate Transparency scanning

CT shard scans download public certificate-log tiles from the CT logs pinned in the network's `ct-logs` evidence. They are **opt-in**:

```toml
[resources]
ct_scanning = true          # accept ct-shard-scan tasks
ct_fetch_kib_per_sec = 256  # download budget for CT tiles
```

Expect about 645 B of download per scanned certificate (gzip), roughly 165 KB per 256-entry tile. If you enable it, allow outbound HTTPS from the worker only to the pinned log hosts. Details: [ct-monitoring.md](ct-monitoring.md).

## 2b. Optional: running an independent verifier

An organisation can also verify the network's work itself. A verifier never runs tasks for
others and needs no CPU budget beyond recomputing them, which is about 20–30 µs per domain
plus, for CT shards, a few re-scanned tiles. Releases need matching records from the
manifest's `min_verifiers` distinct verifier organisations, so each extra verifier removes
trust from the coordinator.

1. **Enrol a verifier key.** Generate it on the verifier host with
   `sudo -u cybermesh cybermesh keygen --out /etc/cybermesh/keys/verifier.key.json` and send the
   public key (`cybermesh key-info`) to governance. Governance adds a member with role `verifier` for your
   operator and, once enough organisations run verifiers, raises `"min_verifiers"` in the
   manifest. Keep at least one more verifier than `min_verifiers` running, or publication
   stops while one is down.
2. **Configure** `verifier.toml`:
   ```toml
   network_id = "cybermesh-pilot"
   key = "/etc/cybermesh/keys/verifier.key.json"
   manifest = "/etc/cybermesh/manifest.json"
   governance_root = "/etc/cybermesh/governance-root.json"
   evidence_dir = "/etc/cybermesh/evidence"     # the pinned bundle; must match tasks
   state_dir = "/var/lib/cybermesh-verifier"    # the systemd unit's StateDirectory
   listen = ["/ip4/0.0.0.0/tcp/4200"]
   # Dial the coordinator *and* workers, so no single relay can withhold results from you.
   bootstrap = ["/ip4/198.51.100.10/tcp/4100/p2p/12D3Koo..."]
   result_timeout_secs = 30 # longer than the coordinator's; it settles early when all answered

   [policy]                 # your own classification policy
   min_operators = 3

   [ct_policy]              # optional: CT spot checks with your own secret seed
   spot_check_tiles = 2

   [ct_witness]             # optional: witness CT logs with the other verifiers, to catch a
   logs = ["letsencrypt-willow-2027h1"]  # log showing organisations different trees
   ```
3. **Run it under the hardened systemd unit** in
   [`deploy/systemd/cybermesh-verifier.service`](../deploy/systemd/cybermesh-verifier.service). It
   has the same sandbox as the worker's, with `CPUQuota=25%` and `MemoryMax=512M`:
   ```bash
   sudo cp deploy/systemd/cybermesh-verifier.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now cybermesh-verifier
   ```
   Or run `cybermesh verifier run --config /etc/cybermesh/verifier.toml` directly.
   - It writes its own signed records to `state_dir/records/`.
   - It publishes them on the network's `records` topic.
   - It stores the other verifiers' records it receives in `state_dir/received-records/`.
   - With `[ct_witness]`, it publishes cosigned checkpoints of those logs and compares the others'. A proven split view is written to `state_dir/ct-split-views/`; check one with `cybermesh ct verify-split-view --evidence <dir> <file>` ([ct-monitoring.md](ct-monitoring.md) §3).
   - It writes its counters to `verifier-report.json` on exit.
4. **Build releases from your own node.** Records are exchanged over the network, so your
   organisation's release signer needs only your node's two directories:
   ```bash
   cybermesh release build --records /var/lib/cybermesh-verifier/records/ \
     --records /var/lib/cybermesh-verifier/received-records/ \
     --manifest manifest.json --root governance-root.json --sequence 42 --issued-at "$NOW" --out release.payload
   ```
   - `release build` checks every record again against your current manifest. It skips, and
     names, any record that does not verify, such as one from a since-revoked verifier or one
     whose named verifier did not sign it. `--strict` makes such files an error.
   - Each co-signer builds from its own node and compares the bytes with the others; it
     does not sign a payload it did not build. If the payloads differ, the nodes received
     different records. Compare the releases' `inputs` (record digests) and exchange the
     missing record files.
   - Records larger than the network message limit (256 KiB) stay files only. Their
     counter is `records_too_large`. You can still pass such files with another `--records`.

## 3. Day-to-day control

```bash
cybermesh worker status --state-dir /var/lib/cybermesh     # live state, CPU, RSS, network counters
cybermesh worker pause  --control-dir /var/lib/cybermesh/control   # stop taking tasks (stays connected)
cybermesh worker resume --control-dir /var/lib/cybermesh/control
cybermesh worker stop   --control-dir /var/lib/cybermesh/control   # exits within ~250 ms
sudo systemctl stop cybermesh-worker                         # immediate shutdown (SIGTERM)
```

## 4. Leaving the network or reacting to compromise

- **Leaving.** Stop the service and ask governance to remove the member from the next manifest.
- **Suspected key compromise.** Stop the worker and ask governance to add the key id to `revocations`. Nodes re-read and re-verify their manifest file every 60 seconds. Once the new manifest is deployed, they disconnect the revoked peer and reject its messages. A node whose own key is revoked stops. Then generate a new key and re-enrol.
- **Quarantine.** If the verifier quarantines your worker for a provable fault, the verification record names the evidence: the signed result digests. Investigate, fix and ask governance to reinstate the worker. Reinstatement is the documented appeals path for operators.

## 5. Platform support

| Platform | Status |
|---|---|
| Linux (x86_64, aarch64) | Supported: systemd unit, cgroup limits, Docker image |
| macOS | Builds and runs (used for development). The governor measures process CPU time and reads load via `sysctl`. Use `launchd` with `LowPriorityIO` and `ProcessType=Background`; there is no hard CPU cap without third-party tools. |
| Windows | Not yet tested. Planned path: run as a Windows service under a low-privilege virtual account and enforce CPU and memory with a Job Object (`JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`, `JobMemoryLimit`). On Windows the governor's load check is disabled. |

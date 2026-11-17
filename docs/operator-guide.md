# Operator guide: enrolling an organisation-controlled worker

This guide is for an organisation that wants to contribute a worker to a CyberMesh network.
Participation is opt-in and can be paused or stopped at any time.

## 1. What a worker does and does not do

| Does | Does not |
|---|---|
| Connects to enrolled peers only (allowlist from the governance-signed manifest) | Accept connections from unknown peers |
| Accepts signed `domain-risk-assessment` tasks from the enrolled issuer | Run code, scripts, URLs or commands from the network |
| Analyses domain *names* against locally pinned public evidence | Fetch, resolve or contact the domains it analyses |
| Signs and publishes its results; sends heartbeats | Read browser histories, documents, credentials or security logs |
| Stays within the CPU, memory, bandwidth and working-hour limits you set | Act as a proxy, crawler or scanner |

## 2. Enrolment procedure

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
   *Note:* `/dns4/` bootstrap addresses need DNS support in the transport. The MVP build supports `/ip4/` and `/ip6/` only, and `/dns4/` is on the roadmap. Use IP addresses for now.
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

1. **Enrol a verifier key.** Generate it with `cybermesh keygen --out verifier.key.json` and
   send the public key to governance. Governance adds a member with role `verifier` for your
   operator and, once enough organisations run verifiers, raises `"min_verifiers"` in the
   manifest. Keep at least one more verifier than `min_verifiers` running, or publication
   stops while one is down.
2. **Configure** `verifier.toml`:
   ```toml
   network_id = "cybermesh-pilot"
   key = "/etc/cybermesh/verifier.key.json"
   manifest = "/etc/cybermesh/manifest.json"
   governance_root = "/etc/cybermesh/governance-root.json"
   evidence_dir = "/var/lib/cybermesh/evidence"   # the pinned bundle; must match tasks
   state_dir = "/var/lib/cybermesh/verifier"
   listen = ["/ip4/0.0.0.0/tcp/4200"]
   # Dial the coordinator *and* workers, so no single relay can withhold results from you.
   bootstrap = ["/ip4/198.51.100.10/tcp/4100/p2p/12D3Koo..."]
   result_timeout_secs = 15

   [policy]                 # your own classification policy
   min_operators = 3

   [ct_policy]              # optional: CT spot checks with your own secret seed
   spot_check_tiles = 2
   ```
3. **Run** `cybermesh verifier run --config verifier.toml`. It writes signed records to
   `state_dir/records/` and its counters to `verifier-report.json` on exit.
4. **Publish your records** to the release signers (for example over HTTPS or rsync). They
   build with one `--records` directory per verifier organisation:
   ```bash
   cybermesh release build --records coordinator-records/ --records org-b-records/ \
     --manifest manifest.json --root governance-root.json --sequence 42 --issued-at "$NOW" --out release.payload
   ```
   `release build` refuses any record whose named verifier did not sign it or belongs to
   another operator.

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

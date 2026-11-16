# Demonstration walkthrough

The demonstrations run entirely on your machine against fictional hosts under reserved names (`*.localhost`, `.test`, `example.*`). They make **no** contact with real phishing infrastructure. The one exception is the optional OpenTimestamps step, which contacts public calendars only if you ask it to.

## 1. Local processes

```bash
scripts/demo-local.sh --keep-serving
```

The script runs these steps, and each one corresponds to an item of the MVP brief:

| Step | What happens |
|---|---|
| Setup | `cybermesh demo init` generates three governance keys (2-of-3), five organisations (A–D honest, M simulated compromised), six workers, a coordinator (issuer + verifier) and three release keys (2-of-3). It then signs the manifest. |
| Workers | Six worker processes start. Each enforces a 1 % CPU budget, a 200 MiB memory budget and a 64 KiB/s outbound budget. |
| Tasks | The coordinator issues signed tasks. Each task goes to three workers of distinct organisations. |
| Analysis | Workers analyse the domains in `datasets/demo/domains.txt` with the deterministic engine. |
| Malicious worker | Organisation M's worker signs forged "malicious" verdicts. The verifier recomputes the task and records a provable `IncorrectResult` fault, then quarantines the worker. The affected task is reassigned and verified by honest organisations. |
| Release | Organisations A and B build the release **independently**. `cmp` shows the payloads are byte-identical. Both co-sign the release. |
| Verification | `release verify` checks the 2-of-3 distinct-operator signatures offline and records the anti-rollback state. |
| Anchoring | The release digest is appended to the Merkle log. The checkpoint is anchored on the local test chain. An inclusion proof is produced and verified offline. |
| Serving | `public/release.json` and the phishing test page are served on `127.0.0.1:8088`. |

Expected release content:

```
warn  medium  4900 examplebank-account-verify.phish.localhost    (lexical only: advisory)
block high   10000 examplebank-billing-update.phish.localhost    (feed + lexical)
warn  medium  4900 examplebank-password-reset.phish.localhost    (lexical only)
block high   10000 examplebank-secure-login.phish.localhost      (feed + lexical)
block high    9000 malware-drop.example.net                      (feed)
warn  medium  8500 xn--exmplebank-login-udn.test                 (Cyrillic homograph; no feed → advisory)
```

These are **not** published:
- `www.google.com`, a deliberate feed false positive on a popular domain;
- `examplebank.test`, the legitimate brand domain;
- unrelated hosts.

## 2. Browser extension

```bash
cd apps/browser-extension
npm ci && npm run build -- --trust-root ../../demo-out/trust-root.json --release-url http://127.0.0.1:8088/release.json
```

1. Load `apps/browser-extension/dist` in `chrome://extensions` (Developer mode → Load unpacked).
2. Open the popup. It shows the release sequence, the signing operators and the entry counts.
3. Visit `http://examplebank-secure-login.phish.localhost:8088/`. You get an interstitial that explains the listing ("high confidence, corroborated by a reference feed"), the signing organisations, and options to go back, continue, or report a false positive.
4. Visit `http://examplebank-account-verify.phish.localhost:8088/`. You get an advisory warning, which you can dismiss.
5. Enable **strict mode** in the popup, then revisit step 3. "Continue" is no longer offered for `block` entries.
6. Stop `scripts/demo-local.sh` (the server). Protection continues from the cached, verified release until it expires.

## 3. Disconnection and reassignment

`cargo test -p cybermesh-tests --test integration disconnected_worker_is_replaced_by_reassignment` starts a real network, kills an assigned worker, and shows the task being settled by the remaining organisations.

## 4. Docker Compose

```bash
deploy/docker/demo.sh up     # build image, start 6 workers, run coordinator, release, anchor, serve
deploy/docker/demo.sh down   # remove containers and the demo volume
```

Each container mounts:
- the shared, non-secret files read-only;
- **only its own key**, read-only;
- only its own state directory, read-write.

The two release signers run as separate containers, each holding one organisation's key. The web container sees only the published files. Docker Engine 26 or later is required, for volume subpaths.

The containers run as a non-root user with:
- a read-only root filesystem;
- all capabilities dropped and `no-new-privileges`;
- cgroup caps of `cpus: 0.10` and `mem_limit: 200m`;
- a static network with fixed IP addresses.

## 5. Optional: OpenTimestamps

```bash
cd demo-out
cybermesh anchor commit --log anchor-log.json --log-id cybermesh-demo --adapter ots --out anchor-receipt-ots.json
cybermesh anchor verify --proof inclusion-proof.json --receipt anchor-receipt-ots.json --release release-1.json
```

This sends one blinded 32-byte hash to the public OpenTimestamps calendars and prints a `pending` status. After a few hours, a Bitcoin attestation can be fetched. Compare it with your own node's block header.

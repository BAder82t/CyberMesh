# Evaluation

**Question.** Can spare computing capacity contributed by independent organisations produce verifiable threat intelligence that measurably improves security protection for ordinary internet users?

**Short answer from v0.1.0.**

- *Verifiable*: **yes**. The verification and distribution design works end to end on a real network, including against adversarial workers, as sections 3 and 6 show.
- *Measurably improves protection*: **only marginally** with the current lexical engine. On phishing domains that a reference feed had not yet listed, it raises an advisory warning for **4.7 %** (held-out) at a **0.026 %** false-positive rate.
- *Spare computing capacity*: **not needed** for this task type. One core assesses about 37,000–52,000 domains per second, and the verifier recomputes everything anyway. Section 5 explains this and proposes a workload where contributed capacity would matter.

All numbers below come from commands in this repository. Raw results are in [`docs/evaluation-results/`](evaluation-results/).

## 1. Data and method

| Item | Value |
|---|---|
| Phishing source | `mitchellkrogza/Phishing.Database` (MIT), `phishing-domains-ACTIVE.txt` at two pinned commits |
| T0 snapshot (feed baseline's knowledge) | commit `4bf912033505180b0d0fd40c54ada55a907ae505` (2026-07-29): 386,048 domains |
| T1 snapshot | commit `12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7` (2026-10-02): 386,604 domains |
| **Unseen phishing** (in T1, not in T0) | **571 domains** |
| Benign | 60,000 domains sampled from Majestic Million ranks 20,001–1,000,000 (CC BY 3.0), excluding anything listed in T0 or T1 |
| Known phishing sample | 20,000 domains in both T0 and T1 (coverage check) |
| Popularity evidence | Majestic Million ranks 1–10,000 (disjoint from the benign sample) |
| Splits | SHA-256 bucket of the domain: dev 60 %, validation 20 %, held-out 20 % |
| Input digests | [`evaluation-results/input-SHA256SUMS`](evaluation-results/input-SHA256SUMS) |

Reproduce:

```bash
scripts/fetch-eval-data.sh && python3 -I scripts/build-eval-sets.py
cargo run --release -p cybermesh-cli -- evidence pin --dir eval-data/evidence
for s in dev validation heldout; do
  cargo run --release -p cybermesh-cli -- eval --evidence eval-data/evidence --dataset eval-data/dataset.csv --split $s
done
cargo run --release -p cybermesh-cli -- eval --evidence eval-data/evidence --dataset eval-data/known.csv --split known
```

**Detectors compared:**

- **feed-only**: the baseline, which flags what the T0 feed lists.
- **lexical-only**: lexical signals of at least 4000 bp, ignoring the feed.
- **engine-malicious**: what CyberMesh may *block*, and only with corroboration.
- **engine-suspicious**: what CyberMesh may *warn* on.

Engine 0.4.0 stops counting plain truncations of a brand token as lookalikes, so `cloud` no longer matches `icloud`. The change came from false positives seen in real CT data, not from the evaluation splits. It also lowered lexical recall on known phishing from 6.4 % to 6.1 %.

**Tuning disclosure.**

- The scoring weights were fixed before any of this data was examined.
- Engine 0.2.0 was measured once on all splits.
- Two changes were then made: a hosting-platform evidence list, and a cryptocurrency wallet and exchange brand category. They were derived only from (a) the **dev** split's misses and (b) the known-phishing coverage analysis.
- No held-out examples were inspected at any point.
- Results for both engine versions are reported.

## 2. Protection quality

### 2.1 Unseen phishing (the question that matters)

| Split | Rows (mal/benign) | Engine | Detector | TP | FP | Recall | Precision | FPR |
|---|---|---|---|---|---|---|---|---|
| dev | 351 / 36,739 | 0.2.0 | engine-suspicious | 2 | 7 | 0.6 % | 22 % | 0.019 % |
| dev | 351 / 36,739 | **0.3.0** | engine-suspicious | 8 | 7 | 2.3 % | 53 % | 0.019 % |
| validation | 114 / 11,616 | 0.2.0 | engine-suspicious | 1 | 2 | 0.9 % | 33 % | 0.017 % |
| validation | 114 / 11,616 | **0.3.0** | engine-suspicious | 4 | 3 | 3.5 % | 57 % | 0.026 % |
| held-out | 106 / 11,645 | 0.2.0 | engine-suspicious | 1 | 3 | 0.9 % | 25 % | 0.026 % |
| held-out | 106 / 11,645 | 0.3.0 | engine-suspicious | 5 | 3 | 4.7 % | 62.5 % | 0.026 % |
| dev | 351 / 36,739 | 0.4.0 | engine-suspicious | 8 | 5 | 2.3 % | 61.5 % | 0.014 % |
| validation | 114 / 11,616 | 0.4.0 | engine-suspicious | 4 | 2 | 3.5 % | 66.7 % | 0.017 % |
| **held-out** | 106 / 11,645 | **0.4.0** | engine-suspicious | **5** | **3** | **4.7 %** | **62.5 %** | **0.026 %** |
| any | — | any | feed-only | 0 | 0 | 0 % (by construction) | — | 0 % |
| any | — | any | engine-malicious | 0 | 0 | 0 % | — | 0 % |

**Reading.**

- The feed baseline cannot know unseen domains. CyberMesh flags a small fraction of them *before* the feed lists them, and only as **advisory warnings**. Block requires feed corroboration by design, which is why engine-malicious is 0 % here.
- Precision depends on the base rate: about 1 % phishing in this sample.
- The false positives are mostly brand typosquats that are not in the phishing list, for example `gogole.com`, `goole.com`, `insagram.com` and `mazon.org`. Many of those are defensive or parked registrations. Warning on them is arguable, but they count against precision here.
- **Most unseen phishing names carry no lexical signal**:
  - random or compromised-looking names such as `awthestatueon.org` and `cargetnow.com`;
  - campaign names for brands not in the table, for example a regional traffic-fine scam (`ncap.*`, `mmda*`).

  Lexical analysis alone is a weak detector. This is consistent with prior work, which needs URL paths, page content or registration data to reach useful recall.

### 2.2 Known phishing (coverage of feed-listed domains)

| Engine | Detector | Recall on 19,967 known phishing domains |
|---|---|---|
| 0.2.0 | feed-only | 99.96 % |
| 0.2.0 | engine-malicious (block-eligible) | 92.8 % |
| 0.3.0 | engine-malicious (block-eligible) | **98.8 %** |
| 0.3.0 | lexical-only | 6.4 % |

The gap between feed-only and engine-malicious is the **popularity exemption**:

- In 0.2.0 the exemption hid 7 % of feed-listed phishing hosts on user-content platforms (`*.weebly.com`, `*.000webhostapp.com`, `*.glitch.me`). These platforms are popular but are not in the Public Suffix List's private section.
- The `hosting-platforms` evidence list in 0.3.0 removes most of that gap, while keeping `drive.google.com`-style feed entries unpublished.
- The remaining 1.2 % are feed entries on popular registrable domains. Blocking them would break major services, so withholding them is deliberate.

## 3. Network and verification performance

| Measurement | Result | Source |
|---|---|---|
| End-to-end pipeline on real libp2p (4 operators, 12 domains, tasks → verified records → co-signed release → anchor) | passes in about 2.5 s | `tests/integration::full_pipeline_over_libp2p` |
| Issue-to-settle latency per task (Docker demo, 6 workers) | 478–642 ms; a task that hits a faulty worker settles after the 15 s result timeout and reassignment | `deploy/docker/demo.sh` |
| Scale run: 15 workers, 5 operators, 312 domains (release build) | 10/10 tasks verified in 2.4 s; settle latency p50 262 ms, p95 510 ms; about 2.7 KB of total network traffic per domain, counting all nodes | `tests/performance` |
| Sustained run: 3,000 domains, 5 workers, 4 operators, separate processes | 94/94 batches verified in 42 s (4 needed one reassignment); 0 messages dropped | `scripts/measure-resources.sh` |
| Behaviour under node failure | assigned worker killed → task settles with the remaining 3 operators, 0 false faults | `disconnected_worker_is_replaced_by_reassignment` |
| Behaviour under malicious submissions | forged verdicts → `IncorrectResult` fault, quarantine, reassignment; equivocation proven with both signed digests (also after settlement); forged signatures rejected; replays never accepted | `tests/adversarial/*` |

## 4. Worker resource usage

Target: about 1 % of one core averaged over 60 s, 100–200 MiB of memory.

| Setting | CPU (average, whole process) | Memory | Network |
|---|---|---|---|
| Local demo (macOS, 6 processes, about 30 s including start-up) | 0.075–0.087 % (self-reported) | 12.5–12.8 MiB RSS | 4–13 KiB out per worker |
| Docker demo (Linux containers, `cpus: 0.10`, `mem_limit: 200m`) | 0.23–0.26 % (self-reported); `docker stats` snapshot 0.19–0.28 % | about 9 MiB RSS; 2.6–2.9 MiB cgroup memory | 7–16 kB per container |
| Sustained run (3,000 domains in 42 s, then 120 s idle; macOS, separate processes) | 0.089–0.111 % self-reported average over 160 s; 0.027–0.056 % by external `ps` sampling | 11.5–11.9 MiB RSS (self-reported); peak 13.8–14.2 MiB (`ps`) | 235–469 KiB out, 224 KiB in per worker over 160 s |
| Docker demo with per-service isolation (second run) | 0.23–0.28 % self-reported; `docker stats` 0.17–0.28 % | 8.7–9.3 MiB RSS; about 2.5 MiB cgroup memory | 3.7–12 kB per container |

**Notes.**

- **CPU.** The worker governor enforces its budget on measured *process* CPU, including networking, and the unit test `cpu_budget_throttles_busy_work` covers it. In these runs the budget was never reached: analysis costs about 20–30 µs of CPU per domain, and most of a worker's CPU goes to libp2p heartbeats and gossip.
- **Short runs can exceed 1 %.** The governor is a token bucket with up to `cpu_window_secs` (default 60 s) of burst credit. A worker can spend that credit at once, for example on a CT scan right after start-up. In one early CT demo run, a worker averaged 2.6 % over its short life. At that time the CT scan also ignored throttling; it now waits while the worker is throttled. The budget holds over long runs (about 1 %), and any 60 s window is bounded at about twice the budget (≈ 2 %).
- **OS enforcement.** OS-level caps (systemd `CPUQuota`/`MemoryMax`, Docker `cpus`/`mem_limit`) were applied in the Docker demo. The local demo used only the cooperative governor.
- **Impact on ordinary workstation activity.** This was not measured with a user-facing benchmark. The average CPU is below 0.3 % of one core, and the worker pauses when load per CPU exceeds the configured threshold.

## 5. Does decentralised computation help?

**For this task type, no.** The facts:

- **Throughput.** One core assesses 36,900 domains per second with the full evaluation evidence (a 386,000-entry feed), or 51,600 per second with the demo evidence (`cybermesh bench`). At a 1 % budget a *single* worker covers about 1.3 million domains per hour. That exceeds the daily volume of newly registered domains across all TLDs.
- **Recomputation.** The verifier recomputes every task: this is required to make collusion harmless, as the internal review found. The workers' computation is therefore redundant by construction.
- **Network value.** What the network adds is *independent attestation by several organisations*:
  - signed, attributable results;
  - detection and quarantine of misbehaving participants;
  - releases that no single key or organisation can forge, co-built and co-signed by independent parties.

  That is a governance and integrity benefit, and it would hold equally with each organisation running one tiny worker.

**A narrower and better use case** for donated capacity is a workload that is heavy, parallel, based on public data and safe to run:

- **Certificate Transparency lookalike monitoring.** Shard public CT logs across workers, match names against the protected-brand and confusables tables, and publish newly certified lookalike domains. These often appear hours before the phishing site goes live.
- **Verification.** It would use sampled re-execution by a second operator, plus the CT tree head as proof of range coverage, because full recomputation would be too expensive.

This is the main item on the [roadmap](roadmap.md) for v0.3.

The first sustained-load run uncovered a **liveness bug**, since fixed. The coordinator's per-author rate limit dropped bursts of large results. The workers concerned then looked unresponsive and were excluded from retries, which left too few distinct operators to reassign the batch, and that batch blocked the whole queue. The fix has three parts:

- exclusion is now only a preference;
- an unassignable batch is moved to the back of the queue and abandoned, with a count in the report, after a bounded time;
- the rate allowance is sized above the workers' own bandwidth budget.

Regression tests: `sustained_load_settles_every_batch`, `unassignable_batches_are_abandoned_not_stalled`.

## 5a. Certificate Transparency monitoring

[ct-monitoring.md](ct-monitoring.md) holds the measurements on real logs. In summary:

- **Parsing.** 15,360 real certificates and precertificates parsed with 0 failures, and **60 of 60** tile Merkle roots matched the logs' own hash tiles.
- **Cost.** 70–105 µs of CPU and about 645 B on the wire (gzip) per entry.
- **Volume.** All tiled logs together grow by about 243 M entries per day. Following them needs about 0.2–0.3 of a core and about 15 Mbit/s, which is about 20–30 workers at a 1 % CPU budget.
- **Value.** This is the first workload where pooled donated slices are a natural fit, though one dedicated server could also run it.
- **Brand signals on real data.** These were dominated by brand owners' own infrastructure, so CT findings go to an investigation report by default instead of becoming browser warnings.

## 6. Security validation

| Property | Result | Evidence |
|---|---|---|
| Reject forged tasks (wrong role, unknown key, wrong type, tampered, mismatched issuer) | 100 % rejected in tests | `forged_tasks_are_rejected` |
| Replay resistance | replay cache, attempt binding, author-bound gossip ids; replays never accepted on the live network | `replay_cache_rejects_redelivered_task`, `replayed_results_are_rejected` |
| No unauthorised code execution | no code-bearing task kinds; engine has no I/O | design and code review |
| False-result injection | single and colluding (3-operator) forgeries: never `block`; caught by recomputation | `colluding_operators_cannot_cause_block`, `colluders_cannot_turn_…` |
| Signature and release verification | RFC 8032 vector, DSSE PAE vector, threshold, distinct operators, revocation, expiry, anti-rollback, fork and equivocation, text validation; extension cross-checks the same vectors | `cybermesh-crypto`, `cybermesh-intelligence/tests/release.rs`, extension unit tests |
| Parser robustness | property tests in every crate; fuzzing: envelope 5.2 M, task 5.8 M, release 5.1 M, OTS 1.9 M, domain 1.3 M executions, 0 crashes or hangs (45 s each; macOS without sanitiser, because the macOS ASan runtime hangs at start-up on this host; CI fuzzes on Linux with ASan) | `fuzz/` |

## 7. Limitations

- **Small unseen set.** 571 unseen phishing domains give wide confidence intervals: a 95 % Wilson interval on held-out recall (5/106) is 2.0–10.6 %. The phishing source changes slowly and stopped updating on 2026-10-02.
- **Label noise.** Benign samples from the Majestic Million may include parked, compromised or defensively registered lookalikes. The phishing list may include sites that have since been cleaned.
- **Domain-level only.** No URL path or page content is analysed, so phishing on legitimate hosts under specific paths is not covered.
- **Not an end-user study.** Protection was not measured in front of users, and warning-dismissal behaviour is unknown.
- **No external audit.**
- **No live public-chain test.** The OpenTimestamps adapter was not exercised against public calendars in automated tests.
- **Platform coverage.** The browser extension end-to-end test runs on Chromium only.

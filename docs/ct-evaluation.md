# CT detection evaluation

> **Status.** The method below was fixed on 2026-11-18, before any results were examined. Results go in §8 once the run ends, and any change to the method will be listed there with its reason.

**Questions.**

1. Does CyberMesh's CT monitoring flag phishing domains **before** independent services confirm them, and how many does it catch?
2. How many of its flags are false alarms?
3. What does distributing the work across a CyberMesh network cost, compared with one server (§6)?

The [general evaluation](evaluation.md) found that the lexical engine catches 4.7 % of unseen phishing domains. That figure is for domain names from a phishing list. This evaluation measures the CT path on live certificates, against confirmations that arrive later.

## 1. Setup

| Item | Value |
|---|---|
| CT logs | Let's Encrypt Willow 2027h1, Let's Encrypt Sycamore 2027h1, Google ParcelYard 2027h1 (static CT, about 230–260 new entries per second each) |
| CT window | 7 days from the start recorded in `runs.jsonl` (UTC). Feed snapshots continue for 3 more days. |
| Tool | `cybermesh ct watch`: one process. Every checkpoint is verified against the pinned key, must be fresh and must extend the previous one; every tile root is proven. Every certificate name is stored. |
| Engine | `ENGINE_VERSION` 0.4.0, unchanged during the run |
| Evidence | 37 protected brands; Majestic top-10,000 popularity list; hosting-platform list; reference feed = `Phishing.Database` snapshot of 2026-07-29 (385,529 domains). Digests are pinned in `runs.jsonl`. |
| Machine | Azure `Standard_B2als_v2` (Sweden Central), Ubuntu 24.04, started with `scripts/ct-eval.sh start` |

The watcher flags exactly the names that the network's `ct-shard-scan` task flags, without that task's per-tile caps (a unit test checks this). There are three flag levels:

- **signal**: any brand-signal finding (impersonation, lookalike, IDN homograph). These go to the investigation report.
- **warn**: verdict `suspicious` or `malicious`, which is what an advisory warning would be based on.
- **block**: verdict `malicious`.

## 2. Ground truth: independently confirmed phishing

A hostname is **confirmed** when an independent source lists it.

**Primary sources:**

- **OpenPhish community feed.** Its public git history (`openphish/public_feed`) updates every 12 hours. The confirmation time is the first commit that lists a URL on the host.
- **Google Safe Browsing or PhishTank**, as reported in phishunt.io's hourly feed (`malicious_google`, `malicious_phishtank`). The confirmation time is the first hourly snapshot that shows the flag.

**Secondary (broader) sources** add phishunt's `malicious_urlscan`, `malicious_tweetfeed` and `malicious_openphish` flags. (Clarified on 2026-11-19, before any detection result was examined: phishunt's own OpenPhish flag may reflect OpenPhish's commercial feed, so it is secondary; the primary OpenPhish source is the community feed's git history.)

**Not ground truth:**

- A phishunt listing on its own. phishunt finds candidates in CT logs itself and publishes them "without third-party confirmation". Using it as ground truth would score one CT lookalike detector against another.
- phishunt is used instead as a **peer baseline** (§4).

**Confirmation times are upper bounds.** A source knew at least that early. The resolution is 12 hours for OpenPhish. For the phishunt flags it is about an hour, plus phishunt's own re-check interval (6 hours for active sites).

**Recall window.** Only hosts first confirmed between start + 24 h and the end of the feed snapshots count. The 24-hour burn-in excludes most phishing whose certificate was issued before the run.

## 3. Matching

- Hosts come from the confirmed URLs, normalised with the engine's `normalize_domain`.
- **CT entry.** A host *h* matches an entry if the entry lists *h*, or lists a wildcard `*.w` with *h* = `label.w`.
- **Detection.** The flagged name must be *h* (or a wildcard covering it), in an entry whose log timestamp is before *h*'s confirmation time.
- **Secondary level.** The same, by registrable domain (Public Suffix List, as the engine uses).

## 4. Metrics

All proportions are reported with 95 % Wilson intervals.

- **Observability.** The share of confirmed hosts that have a matching entry in the three logs, with a log timestamp between the start and the confirmation. Phishing on hosting platforms or compromised sites often has no certificate naming the phishing host, so this bounds what any CT monitor can catch.
  - *Breakdown added on 2026-11-20, after the dev-window analysis and before any test-window result.* The report also gives observability and recall for hosts whose own name appears in a certificate. A host covered only by a wildcard certificate for its parent counts as visible under §3, but its name never appears in CT, so no name-based monitor can flag it from there. The pre-registered metrics are unchanged; this is an extra breakdown of them.
- **Recall.** Among observable confirmed hosts, the share flagged before confirmation, at each flag level.
- **Lead time.** The confirmation time minus the log timestamp of the earliest flagged entry: median and quartiles, per source.
- **Detection latency, reported separately.** The scan time minus the log timestamp. This is the operational delay: it includes the time for a 256-entry tile to fill and the poll interval. Gaps while the watcher was down are reported, not hidden.
- **Precision (a lower bound).** Distinct hosts flagged at warn level, with a log timestamp inside the CT window, that a primary source confirms by the end of the feed snapshots. Feeds miss most phishing, so this is a floor, not an estimate.
- **What the false alarms are.**
  - A random sample of 200 unconfirmed warn-level hosts, stratified by brand, is labelled by hand as:
    - brand-owned infrastructure;
    - other legitimate;
    - unknown;
    - likely phishing.
  - Labels come only from the name and from public, non-contact sources: documented brand-owned domains, Majestic rank and CT history.
  - No DNS lookups or HTTP requests are made to the hosts. CyberMesh never contacts suspicious hosts.
- **Comparison with phishunt**, an existing free CT-based detector:
  - the overlap between the hosts each flags;
  - for hosts both flag, CyberMesh's log timestamp against phishunt's `first_seen`;
  - confirmed hosts that one catches and the other misses.

## 5. Engine changes during evaluation

The run records engine 0.4.0 unchanged. Improvements, for example lists of brand owners' own infrastructure, may be derived **only from the first two days** (dev). Revised engines are scored **only on days 3–7** (test), by re-assessing the stored names offline, and are reported next to the shipped engine's results.

### 5.1 Revision 1 (frozen on 2026-11-20)

**What changed.** Revision 1 is engine 0.4.0 with six domains added to the brands' lists of their own domains (`legitimate`). Nothing else in the code or evidence changed.

| Brand | Added |
|---|---|
| amazon | `amazonaws.com.cn`, `amazonwebservices.com.cn`, `amazon.dev` |
| microsoft | `microsoft-int.com` |
| netflix | `netflix.net` |
| chase | `jpmchase.net` |

**How the domains were chosen.** Only certificates logged in the dev window were used, 2026-11-18 18:05 to 2026-11-20 18:05 UTC.
1. **Candidates.** These were the organisation-level domains behind the most warn-level flags. 70 % of all 330,621 such names fell under `amazonaws.com.cn` and `microsoft-int.com` alone.
2. **Rule.** A candidate is added to a brand's list only if at least one certificate in the dev window also names a domain already on that brand's list, or one added by this rule. A CA validates every name on a certificate, so one that names both domains was requested by someone who controls both.

**Evidence for each domain.**

| Added domain | Shares a certificate with |
|---|---|
| `microsoft-int.com` | `microsoft.com` (56) |
| `amazonaws.com.cn` | `amazon.com` (11) |
| `amazonwebservices.com.cn` | `amazonaws.com.cn` (22) |
| `amazon.dev` | `amazon.com` (27), `amazonaws.com` (10) |
| `netflix.net` | `netflix.com` (7) |
| `jpmchase.net` | `jpmchase.com` (123), `jpmorgan.com` (29), `chase.com` (3) |

**Rejected.** These candidates did not meet the rule and stay flagged:
- `amazonaws.eu` and `amazonwebservices.eu`, which share certificates only with each other;
- `amazongamelift.com`, `microsoft-falcon.net` and `ppe-microsoft-falcon.net`, which share certificates with no other domain.

**Considered and not added: new brands.** All 24 visible confirmed hosts that were missed and had a known target were aimed at brands outside the 37 protected ones. But:
- the 18 Allegro hosts were covered only by wildcard certificates, so their names never appeared;
- the other 5 brands (HSBC, DPD, GLS, Bradesco, ING) had one host each.

Adding brands could have gained at most 5 hosts, chosen from the very examples being scored, at an unknown false-alarm cost from short tokens. They were therefore left out.

**Frozen evidence.** The brand list is [`evaluation-results/ct-eval-rev1-brands.json`](evaluation-results/ct-eval-rev1-brands.json): the shipped list (`datasets/demo/evidence/brands.json`, SHA-256 `f174d379…5ec0c`) with the six domains added.
- File SHA-256: `3a43b4f0a460d91b7690304c27f02818193e556e0aaac22dcf54a177e843a217`.
- Pin in the evidence bundle: `sha256:0b2ede82bd042d06fc0f5759da7e3bead1940c7dfa150ce36270fc98864c46e7`.
- The other sources of the bundle are those of the shipped run.

**Effect on the dev window**, re-scored offline with `ct evaluate --rescore-evidence`:

| Days 1–2 | Engine 0.4.0 (shipped) | Revision 1 |
|---|---|---|
| Names flagged at warn level | 330,621 | 87,841 (−73 %) |
| Names flagged at signal level | 376,484 | 132,233 (−65 %) |
| Names flagged at block level | 2,652 | 2,644 |
| Recall (warn) among visible confirmed hosts | 13 / 144 | 13 / 144 |
| Lead time (warn, median) | 24.1 h | 24.1 h |

No detection in the dev window was lost.

The test-window data (days 3–7) had not been examined when revision 1 was frozen. Scripts that read the name store, to find shared certificates and hosts visible under their own name, opened files that also hold later certificates. They used only certificates logged in the dev window.

## 6. Cost of decentralisation

The same range of tiles is processed in two ways:

- (a) by `cybermesh ct watch` as one process;
- (b) by a local CyberMesh network following the same log: a coordinator, *N* workers and one independent verifier, with `min_verifiers = 2`.

Measured for both:
- CPU seconds across all processes;
- bytes downloaded from the log;
- peer-to-peer traffic;
- time from the log timestamp to a verified record.

The question is what independent verification by several organisations costs in extra compute and bandwidth. That is the network's actual benefit, since raw capacity is not ([ct-monitoring.md](ct-monitoring.md)).

## 7. Limitations known in advance

- **Coverage of the sources.**
  - The feeds list only a fraction of all phishing, and they lean towards some brands.
  - The OpenPhish community feed is a subset of OpenPhish's commercial feed.
- **Scope of the CT data.**
  - Only three static CT logs are followed; RFC 6962 logs are not.
  - Let's Encrypt certificates are covered through Willow and Sycamore, but certificates from other CAs only in part.
- **Brands.** Only the 37 brands in the evidence are protected. Phishing against other brands counts against recall.
- **Length.** One week of data.
- **Wildcards and apex hosts.** The stored names do not distinguish a certificate for `*.example.com` alone from one that also names `example.com` itself. A phishing host at a domain's apex can therefore count as visible, and as flagged, from a wildcard-only certificate that does not cover it. This biases observability and recall upwards for apex hosts. Wildcard-only certificates are a minority, and the bias cannot be removed from this run's data. (Recorded on 2026-11-19, from an internal review, before any detection result was examined.)
- **Windows and burn-in.** The 24-hour burn-in applies to any window, including the test window of §5, whose certificates start at its own start.
- **Data terms.**
  - The OpenPhish community feed is for non-commercial use only.
  - Raw feed data and certificate names stay out of the repository (`eval-data/` is git-ignored).
  - Only aggregate results and a few illustrative names are published.

## 8. Results

### 8.1 Detection

*The test-window results (days 3–7) are pending: the CT window ends on 2026-11-25 and feed snapshots end on 2026-11-28. `cybermesh ct evaluate` computes every figure in §4 from the run directory.*

#### Dev window (days 1–2), engine 0.4.0 as shipped

These are tuning-window figures, published for transparency. They are not the evaluation result.
- **Window.** 2026-11-18 18:05 to 2026-11-20 18:05 UTC, about 135 million entries from the three logs, with no downtime.
- **Confirmations.** With the 24-hour burn-in, confirmations cover only the second day: 556 hosts confirmed by the primary sources.

| Measure | Result |
|---|---|
| Confirmed hosts visible in the logs before confirmation | 144 / 556 (25.9 %, 95 % CI 22.4–29.7 %) |
| …of which under their own name | 110 / 556 (19.8 %) |
| Recall (signal / warn / block) among visible hosts | 18, 13 and 6 of 144 (12.5 %, 9.0 %, 4.2 %) |
| Recall (signal / warn / block) among hosts visible under their own name | 18, 13 and 6 of 110 (16.4 %, 11.8 %, 5.5 %) |
| Recall (signal / warn) for the protected brands only | 13 / 13 and 11 / 13 of visible hosts |
| Lead time over confirmation (warn, median) | 24.1 h (IQR 12.4–29.2 h, n = 13) |
| Detection latency (scan minus log time, median) | 10 s |
| Precision floor (warn) | 23 confirmed of 330,621 flagged names |
| phishunt, same hosts | caught 18 of the 110 visible under their own name; listed 114 hosts in the window, 58 of them visible to us first, of which CyberMesh flagged 21, earlier than phishunt's `first_seen` for all 21 (median 10.2 h) |

**Why visible confirmed hosts were missed.** 126 of the 144 visible hosts were missed:
- **34 were covered only by wildcard certificates.** These include all 18 Allegro hosts and 12 on `workers.dev`.
- **87 of the remaining 92 have no known target and no protected brand's token.** Most are random-looking names on `pages.dev` and throwaway domains with no brand word at all.
- **The last 5 target brands outside the 37 protected ones.** These are HSBC, DPD, GLS, Bradesco and ING, one host each.
- **None** of the missed hosts contained a protected brand's token.

So recall is limited by the lexical approach (most phishing names carry no brand word) and by brand coverage, not by missed brand matches.

**Where the false alarms come from.** 70 % of warn-level names fall under two brand-owned domains, `amazonaws.com.cn` and `microsoft-int.com`. The rest are mostly hosting platforms (`pages.dev`, `wasmer.app`, `cpanel.site`, `workers.dev`), where many names look like real phishing that no feed has confirmed. Revision 1 (§5.1) addresses the first group.

### 8.2 Cost of decentralisation (measured 2026-11-19)

**Setup.**
- Data: the 128 most recent full tiles of Let's Encrypt Willow 2027h1 at the time, 32,768 certificates, scanned by `scripts/ct-cost.sh` on one Apple M3 Max laptop.
- Network: a coordinator (org-a), 5 workers in 4 organisations and one independent verifier (org-b).
  - Every tile goes to 2 workers of different organisations, 8 tiles per task.
  - Each verifier rescans 2 tiles per task.
  - Each worker's 1 % CPU budget is enforced.
- Both setups verify the log's checkpoint and prove every tile root they rely on.
- Downloads are what the HTTP client received, after decompression, on both sides.
- Workers are stopped cleanly before their final figures are read.

| | One process | CyberMesh network (7 processes) | Ratio |
|---|---|---|---|
| CPU | 1.3 s (39 µs per certificate) | 4.4 s (135 µs per certificate) | 3.5× |
| Downloaded from the log | 48.6 MB | 119.6 MB | 2.46× |
| Requests to the log | 134 | 493 | 3.7× |
| Peer-to-peer traffic | — | 0.82 MB (25 B per certificate) | — |
| Wall time | 4 s | 100 s | 25× |
| Tasks verified | — | 16 of 16, by both verifiers; 0 faults | — |

**By role.**
- The 5 workers used 3.3 s of CPU and downloaded 97.1 MB, which is 2.0×: every tile is scanned twice.
- The coordinator and the independent verifier each downloaded about 11 MB, 23 % of what one scanner downloads, and used about 0.5 s of CPU each. The coordinator rescanned 28 of the 128 tiles.

**How stable these numbers are.**
- The download ratio is stable: 2.45× in an earlier run of the same size.
- The CPU ratio is not. The earlier run, made while the laptop was compiling, gave 5.4× (7.5 s against 1.4 s). On a machine with fast and slow cores, a busy system moves processes to the slower ones, which raises CPU time for the same work. The table shows the run on a quiet machine.

**What it means.**
- **Download grows with volume.** It is replication (2×) plus the verifiers' spot checks (about 0.46×). Verifying costs about a fifth of scanning, which is the property the CT design depends on.
- **CPU.** The 3.5× includes fixed costs that a short run makes large: each process loads the engine and evidence (0.15 s each, about 1 s for the 7 processes) and exchanges heartbeats for the whole run. The part that grows with volume is the double scan plus the spot checks, about 2.5× by the components above. A long run should come closer to that, but this has not been measured.
- **Wall time** is slow by design: workers are capped at 1 % of a core. Throughput comes from the number of workers. At about 40 µs per certificate, the three logs of §1 (about 800 new entries a second) need about 0.03 of a core in one process, or about 0.07 of a core of worker CPU with replication 2, so at least 7 workers at 1 %.
- **Peer-to-peer traffic** is negligible next to the log download.

**What the extra cost buys.** It doesn't buy capacity: one small server does the job. It buys verification by a second, independent organisation of every task, and releases that no single operator can produce. The price is about 2.5× the download and 2.5–3.5× the CPU of one server.

**Worst case.** With 2 tiles per task, as in the local demo, every verifier rescans every tile (64 tiles: 3.5× the download, 4.5× the CPU). Task size is the knob that sets the cost of verification.

## Reproduce

```bash
cargo build --release -p cybermesh-cli
# eval-data/ct-evidence: the evaluation evidence (see evaluation.md) plus
# datasets/ct-logs/public-static-ct-logs.json as its ct-logs source, then:
target/release/cybermesh evidence pin --dir eval-data/ct-evidence
scripts/ct-eval.sh start      # status | stop | history (after the run)
scripts/ct-eval.sh history    # OpenPhish snapshots from its git history
target/release/cybermesh ct evaluate --run eval-data/ct-run --evidence eval-data/ct-evidence --out eval-data/ct-run/eval
scripts/ct-cost.sh letsencrypt-willow-2027h1 128   # section 8.2
```

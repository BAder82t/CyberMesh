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

**Secondary (broader) sources** add phishunt's `malicious_urlscan` and `malicious_tweetfeed` flags.

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
- **Data terms.**
  - The OpenPhish community feed is for non-commercial use only.
  - Raw feed data and certificate names stay out of the repository (`eval-data/` is git-ignored).
  - Only aggregate results and a few illustrative names are published.

## 8. Results

*Pending: the run started on 2026-11-18.*

## Reproduce

```bash
cargo build --release -p cybermesh-cli
# eval-data/ct-evidence: the evaluation evidence (see evaluation.md) plus
# datasets/ct-logs/public-static-ct-logs.json as its ct-logs source, then:
target/release/cybermesh evidence pin --dir eval-data/ct-evidence
scripts/ct-eval.sh start      # status | stop | history (after the run)
```

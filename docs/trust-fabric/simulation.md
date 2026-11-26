# Trust Fabric: simulation

Status: experimental. Implemented in `crates/cybermesh-sim`. **Every number below is simulated,
not measured on real infrastructure.** The topology, failures, adversary and traffic are
generated from a seed by `SimRng`, a deterministic generator that is **not** secret randomness
and deliberately does not implement the Trust Fabric's `RandomSource` trait, so it cannot be used
as key material by accident.

## What it models

Thousands of participants spread over administrative domains (a ring inside each domain, a ring
across all participants and random cross-domain links); concurrent sessions that compete for the
per-link one-time-pad budgets; random link failures and whole-domain outages (correlated
failures); a static or mobile adversary that corrupts domains; a router that learns of failures
only a tick later and of corruption only after `detect_ticks`; and per-tick provisioning. Each
message is planned with `cybermesh-routing` against what the router **knows** and judged against
the **truth**:

| Outcome | Meaning |
|---|---|
| delivered | reconstructed correctly and not readable by the adversary |
| breached via paths | the adversary held at least `k` shares through corrupt domains on the paths |
| breached at an endpoint | an endpoint's own domain was corrupt (no routing prevents that) |
| no plan | no disjoint paths satisfied the requirement under what the router knew |
| starved | the plan could not be paid for from the secret budgets |
| lost | too many shares were lost or tampered with in transit |

It does **not** run the sharing, MAC or transport code on bytes. It counts shares and budgets
and applies the rules those crates establish (`k` of `n` shares, authenticated or error-corrected
tampering, per-hop pad consumption). Tampering by a corrupt domain is assumed whenever the
requirement says so.

## Reproducing

```text
cargo build --release -p cybermesh-sim
B=target/release/cybermesh-sim; O=docs/trust-fabric/data/sim
$B exp corruption --scenario $O/base.toml      --seed 1 --runs 5 > corruption.csv
$B exp threshold  --scenario $O/base.toml      --seed 1 --runs 5 > threshold.csv
$B exp drain      --scenario $O/base.toml      --seed 1          > drain.csv
$B exp diversity  --scenario $O/diversity.toml --seed 1 --runs 5 > diversity.csv
$B exp mobile     --scenario $O/mobile.toml    --seed 1 --runs 5 > mobile.csv
```

`--runs 5` averages seeds 1 to 5 column by column (the first column is the swept parameter).
The scenario files are in `docs/trust-fabric/data/sim/`; `cybermesh-sim default-scenario`
prints the defaults. The committed CSVs were regenerated after the last source change and are
byte-identical. Same scenario and seed give the same result on every machine (tested).

## Results

Base scenario: 300 participants, 30 domains, 20 sessions, 60 ticks, 512-byte messages, plans for
one corrupt domain (`t = 1`) with authenticated shares (3 disjoint paths).

### Corruption against the assumption (`corruption.csv`)

A static adversary holds `corrupt_domains` domains and the router never learns of it (the worst
case for the plan).

| corrupt_domains | assumed_t | availability | breach_via_paths | breach_endpoint | secret_per_payload |
|---|---|---|---|---|---|
| 0 | 1 | 1 | 0 | 0 | 27.2559 |
| 1 | 1 | 0.9400 | 0 | 0.0600 | 29.1134 |
| 2 | 1 | 0.8600 | 0 | 0.1400 | 31.7981 |
| 3 | 1 | 0.7600 | 0.0500 | 0.1900 | 36.3036 |
| 4 | 1 | 0.6300 | 0.1100 | 0.2600 | 44.1726 |
| 6 | 1 | 0.5100 | 0.1400 | 0.3500 | 55.5652 |
| 8 | 1 | 0.3700 | 0.2100 | 0.4200 | 82.3046 |

* Through the paths, breaches are zero while the corruption is within what the plan assumed
  (tested for every seed 1 to 8 at `c = 1`), and appear once more domains are corrupt than the plan
  assumed. At `c = 2` the assumption is exceeded but a breach also needs two of the three paths to
  cross two different corrupt domains, so none was seen in these runs.
* Endpoint breaches grow with corruption whatever the plan: a corrupt endpoint domain cannot be
  routed around. If the router **knows** the corrupt domains it refuses those sessions instead
  (`no_plan`), so no message is breached (tested): knowledge converts breaches into
  unavailability.
* Secret per payload byte rises with corruption. The metric divides all secret spent by the
  payload of **delivered** messages only, and availability falls, so part of the rise is the
  shrinking denominator; whether longer paths around corrupt domains contribute was not
  separated out.

### Cost against the threshold (`threshold.csv`)

| t | paths_n | wire_per_payload | secret_per_payload | availability | no_plan |
|---|---|---|---|---|---|
| 0 | 1 | 1.0312 | 7.9612 | 1 | 0 |
| 1 | 3 | 3.0938 | 27.2559 | 1 | 0 |
| 2 | 5 | 5.1562 | 44.7047 | 1 | 0 |
| 3 | 7 | 7.2188 | 58.6076 | 0.9000 | 0.1000 |
| 4 | 9 | 9.2812 | 71.2923 | 0.2800 | 0.7200 |

* `paths_n = 2t + 1` as `sharing_parameters` states. Wire bytes per payload byte equal
  `n * (512 + 16) / 512`, exactly (tested), so communication grows linearly with `t`.
* Availability falls at `t >= 3`: this generated sparse topology cannot supply 7 or 9
  domain-disjoint paths for most pairs. That is a property of the topology, not of the protocol:
  a threshold is only as good as the domain connectivity under it.

### Availability against administrative diversity (`diversity.csv`)

The same 600 participants spread over more domains, with random link failures (1% per link per
tick) and domain outages (1% per domain per tick). Scenario: `diversity.toml`.

| domains | availability | no_plan | lost | mean_recovery_ticks |
|---|---|---|---|---|
| 5 | 0.1803 | 0.7893 | 0.0304 | 9.6522 |
| 8 | 0.2208 | 0.7385 | 0.0407 | 8.1359 |
| 12 | 0.3685 | 0.5742 | 0.0573 | 5.0235 |
| 20 | 0.5843 | 0.3533 | 0.0625 | 3.3285 |
| 40 | 0.7588 | 0.1857 | 0.0555 | 2.6806 |
| 80 | 0.8249 | 0.1223 | 0.0528 | 2.4271 |

* Availability rises steadily with the number of domains: with few domains there are not enough
  distinct relay domains for three domain-disjoint paths (`no_plan` dominates), and outages of
  large domains remove more of the network.

### Mobile adversary (`mobile.csv`)

Two corrupt domains at a time, moving with probability `move_prob` per tick, detection after 3
ticks. Scenario: `mobile.toml`.

| move_prob | availability | breach_via_paths | breach_endpoint | mean_recovery_ticks | max_recovery_ticks |
|---|---|---|---|---|---|
| 0 | 0.8862 | 0.0005 | 0.0042 | 1.2000 | 1.2000 |
| 0.0500 | 0.8979 | 0.0030 | 0.0161 | 18.0303 | 32.4000 |
| 0.1000 | 0.8991 | 0.0046 | 0.0292 | 8.7472 | 23.2000 |
| 0.2500 | 0.8817 | 0.0096 | 0.0583 | 4.5200 | 16.2000 |
| 0.5000 | 0.8956 | 0.0103 | 0.0789 | 2.1339 | 7.6000 |
| 1 | 0.8887 | 0.0117 | 0.0997 | 1.1176 | 3.6000 |

* Breaches through the paths and at the endpoints rise as the adversary moves faster than the
  router detects it. A static adversary is excluded after 3 ticks, which is consistent with the
  few path breaches at `move_prob = 0` (not isolated to those ticks).
* The recovery columns are **noisy**: they are means over few events per run and 5 seeds, and
  should not be read as a trend.

### Measured against the bound (`drain.csv`)

One pair, no provisioning, sending until the router can no longer plan; share bytes sent against
`wire_secret_flow` (the max-flow of the initial budgets), seeds 1 to 6.

| seed | paths_n | flow_bound_bytes | measured_bytes | ratio | sends |
|---|---|---|---|---|---|
| 1 | 3 | 10485760 | 9721008 | 0.9271 | 6137 |
| 2 | 3 | 9437184 | 7495488 | 0.7943 | 4732 |
| 3 | 3 | 8388608 | 6698736 | 0.7986 | 4229 |
| 4 | 3 | 11534336 | 11273328 | 0.9774 | 7117 |
| 5 | 3 | 7340032 | 6426288 | 0.8755 | 4057 |
| 6 | 3 | 9437184 | 9190368 | 0.9738 | 5802 |

* The ratio never exceeds 1 (tested for 5 seeds on a smaller budget, and shown here for 6): the
  paths summed are a feasible flow, so this must hold. The planner reaches 79% to 98% of the
  bound, because it takes cheapest paths greedily and does not balance budgets across links.
* The bound is for per-hop one-time-pad forwarding with no coding across paths. It is **not** the
  information-theoretic secret capacity of the network, which is open research.

## Limits

* One generated topology family, a handful of seeds, no confidence intervals. Differences of a
  few percent are not conclusions.
* No congestion or latency model (latency is only a path cost), no concurrent-session
  interference beyond sharing the secret budgets, no changing trust policy during a run.
* The router and adversary are simple: corruption is detected after a fixed delay, failures after
  one tick; nothing probes or infers.
* Thousands of participants run (a 2,000-participant scenario is tested), but the published
  tables use 300 to 600 so that five seeds finish in minutes.

# Internal security review (v0.1.0)

Two independent internal reviews were run on the core crates on 2026-11-16:

- an adversarial security audit;
- a Rust correctness and robustness review.

Both reviewers worked read-only and wrote proof-of-concept tests where they could. This page lists every finding of LOW severity or above and what was done about it. **This is not an external audit.**

## Fixed

| Severity | Finding | Fix | Regression test |
|---|---|---|---|
| HIGH (confirmed) | Three colluding operators could turn a feed false positive on a *popular* domain into a `block`. The non-recomputed path classified from worker-supplied findings, and sampling meant recomputation ran only 25 % of the time. | The verifier always recomputes when it holds matching evidence and classifies only from its own assessment. Without evidence there is no `block`. | `colluders_cannot_turn_a_feed_false_positive_on_a_popular_domain_into_a_block` |
| HIGH (confirmed) | OpenTimestamps parser memory amplification of about 700×: breadth was not bounded and every node stored a 4 KiB message. | Node budget (4096) and stored-byte budget (2 MiB) per proof. | `breadth_amplification_is_bounded`, fuzz target `ots` |
| HIGH (confirmed) | IDN false positives: punycode `xn--` artefacts counted as hyphens and digits, so legitimate internationalised names were scored. | Structural checks skip punycode labels. Engine version bumped. | `legitimate_idns_get_no_structural_findings` |
| HIGH (confirmed) | The rate limiter refused any message of about 50 KiB or more forever, because the cost exceeded the bucket capacity. | Cost is clamped to the burst size. Configs are validated. | `oversized_cost_is_clamped_not_refused_forever` |
| HIGH (plausible) | Engine determinism depended on unpinned PSL/IDNA crate versions. Honest workers on a different lockfile would be quarantined. | Exact `=` pins. Table versions are folded into `ENGINE_VERSION`. Golden-vector digest test. | `golden_vectors` |
| MEDIUM | Gossip message id was `SHA256(data)`, so a peer could pre-claim and poison an honest message's id. | The id is `H(author ‖ data)`. Rate limiting is per author, not per relay. | `allowlisted_peers_exchange_messages` (network) |
| MEDIUM (confirmed) | URL normaliser took the *first* `://` anywhere, so `evil.com/?u=http://good.com` normalised to `good.com`. | `://` counts only after a valid RFC 3986 scheme. | `embedded_urls_do_not_change_the_host` |
| MEDIUM | Worker free text flowed unvalidated into releases. | Classification uses verifier text. Consumers enforce printable ASCII, length caps and bounded lists. The extension renders text with `textContent` only. | `consumer_detects_forks_and_bad_text` |
| MEDIUM | Evidence pins bound only file bytes, so relabelling a blocklist as a popularity list kept the pins. | Pin = `H(id, kind, file digest)`. | `relabelling_a_source_changes_its_pin` |
| MEDIUM | No release lifetime cap, no `previous`-chain check, unbounded sequence jumps. | TTL ≤ 30 days, fork detection, jumps ≤ 10⁶. | `consumer_detects_forks_and_bad_text`, `hostile_parameters_are_rejected_not_wrapped` |
| MEDIUM | Arithmetic overflow in `issued_at + ttl` and record-age checks, plus rate-limiter refill maths. | `checked_add` / `saturating_*` throughout. | `hostile_parameters_are_rejected_not_wrapped` |
| MEDIUM | `outbound_bytes_per_sec = Some(0)` panicked. | Rejected at setup. | (setup validation) |
| MEDIUM | `testkit` (label-derived keys) compiled into production builds, and silent `unwrap_or_default` signing. | Feature-gated (`testkit`, `dev-tools`). Loud failures in test code. | build without features |
| MEDIUM | If local encoding failed, `finalize` could fault every honest worker. | Recompute only when encoding succeeds. Otherwise no faults are recorded. | covered by verifier tests |
| MEDIUM | Appeals ignored subdomains, and an upheld appeal could block real re-listing forever. | An appeal covers subdomains. Re-listing needs a fresh, feed-corroborated `block` dated after the decision. | `appeal_covers_subdomains_and_only_fresh_block_relists` |
| MEDIUM | OTS `upgrade` fetched attacker-chosen URIs (blind SSRF) and could recurse without bound. | Configured calendars only, at most 16 requests, no traversal of fetched data, upgraded pending attestation replaced. | code review |
| LOW | Unbounded `rejected` list per task. | Capped at 64 plus an overflow counter. | `rejection_log_is_bounded_under_flooding` |
| LOW | Evidence loading followed symlinks and had a TOCTOU race and no aggregate cap. | Regular files only, bounded `take()` reads, 256 MiB bundle cap, 16 sources, strict file names. | `refuses_symlinked_sources` |
| LOW | Key file permission check race, symlinks followed, partial file left on write failure. | `O_NOFOLLOW` plus `fstat` on the open handle, size cap, cleanup on failure. | `key_file_roundtrip_and_permissions` |
| LOW | Predictable `.tmp` names for atomic writes. | Exclusive (`create_new`) random temp names, fsync, rename. | — |
| LOW | System clock before the epoch failed open (nothing expired). | Fails closed. | — |
| LOW | `ReputationBook::apply` double-counted. | Idempotent per record. | `reputation_apply_is_idempotent` |
| LOW | Varint overflow and trailing attestation bytes accepted (malleable proofs). | Rejected. | `varuint_overflow_and_trailing_attestation_bytes_are_rejected` |
| LOW | Manifest accepted any `issued_at` and any lifetime. | Skew ≤ 300 s, lifetime ≤ 400 days. | — |
| LOW | Transparency log did not reject duplicate digests on load. | Rejected. | — |

Findings from the end-to-end adversarial tests (same session):

| Finding | Fix | Test |
|---|---|---|
| An equivocating result that arrived *after* the task settled was silently ignored. | The coordinator keeps per-worker accepted digests for settled tasks and records a provable late-equivocation fault, which quarantines the worker. | `equivocation_is_proven_with_both_signed_results` |
| Replays were dropped but not counted. | Counted (`results_replayed`). Transport-level deduplication documented. | `replayed_results_are_rejected` |
| Phishing on user-content hosts (`*.weebly.com`) was exempted by the platform's popularity. | `hosting-platforms` evidence kind (engine 0.3.0). | `customer_sites_on_hosting_platforms_are_not_exempted` |

## Second pass: node runtimes, CLI, browser extension, deployment

A second independent internal review covered code written after the first pass. It found no CRITICAL or HIGH issues, and the fixes below address its findings.

| Severity | Finding | Fix | Test or evidence |
|---|---|---|---|
| MEDIUM (confirmed) | `adversary-sim` was unified into ordinary workspace builds through the tests crate, so a root `cargo build` produced a CLI that honoured adversary configs. | The feature moved to a dev-dependency. The demo builds into `target/demo`. CI asserts that the default build refuses adversary configs. | CI step; `cargo tree` shows no `adversary-sim` in the normal graph |
| MEDIUM (confirmed) | Nodes never reloaded the trust manifest, so revoked keys stayed trusted until restart. | The manifest is re-verified every 60 s and only a strictly newer sequence is accepted. Same-sequence equivocation is flagged. The live allowlist update disconnects revoked peers. A node whose own key is revoked stops. Expired manifests stop task processing. | `reload_accepts_only_newer_manifests_and_flags_equivocation`, `revoked_peer_is_disconnected_and_ignored` |
| MEDIUM (confirmed) | Quarantines were persisted only on clean shutdown. | `reputation.json` is written atomically after every change. | — |
| MEDIUM | The late-equivocation proof ignored the task digest, so another issuer reusing a task id could frame an honest worker. | The proof requires the same task digest and attempt. | `equivocation_is_proven_with_both_signed_results` |
| MEDIUM | The late-equivocation path could be flooded. | Replay-cached, skipped for workers that are already quarantined, list capped. | — |
| MEDIUM (confirmed) | `cybermesh serve` returned `*.key.json` files and followed symlinks out of the served directory. | Extension allowlist, key files refused, path canonicalised and prefix-checked, non-loopback binds need `--public`. | `key_files_symlink_escapes_and_unknown_types_are_refused` |
| MEDIUM (confirmed) | The extension build silently fell back to the public test trust root. | `--trust-root` or an explicit `--dev-trust-root` is required. The build warns about thresholds below 2. | build script |
| MEDIUM | A "Continue anyway" exception for a host could override a more specific listed host beneath it. | The DNR allow rule excludes more specific indicators. Exceptions must match the same entry and are revoked when the listing set changes. | extension test `a "continue" exception ... never covers a more specific listed host` |
| MEDIUM | All Compose containers mounted the whole key volume. | Volume subpaths: each service gets only its own key (read-only) and its own state. The web container sees only `public/`. | Verified in a running demo (`ls /demo/keys` inside `worker-m1`) |
| LOW | `appeal decide` accepted non-ASCII text, producing releases that consumers rejected. | Validated in the CLI and in the release builder. | — |
| LOW | Governor accepted NaN or overflowing limits. | Validated. | — |
| LOW | Unresponsive workers were never deprioritised. | Missed-assignment counters. Workers with 3 or more consecutive misses are avoided when alternatives exist. | — |
| LOW | `tabs` permission was broader than needed. | `activeTab`. | extension end-to-end test (14/14) |
| LOW | Supply chain: base images, gitleaks image and the nightly fuzz toolchain were unpinned, the gitleaks allowlist was broad, and evaluation inputs were unverified. | Digests and versions pinned, allowlist narrowed, phishing snapshots verified against pinned SHA-256. | CI files |
| LOW | `.dockerignore` missed `fuzz/target` and other outputs, giving a 642 MB build context. | Excluded. | — |

## Accepted or deferred (documented residual risk)

- **Manifest state on restart.** A node that restarts loads whatever manifest file is on disk; it does not persist the highest sequence it has seen across restarts.
- **Extension trust root.** The extension's trust root is bundled, so a revoked release key is removed only by shipping an extension update.
- **Synchronous analysis.** `assess_task` runs on the worker's async loop. It costs about 1 ms per 32-domain task.
- **Gossipsub peer scoring is not enabled.** Bad messages are rejected but the sender's mesh score is not reduced.
- **`RUSTSEC-2024-0436`.** `paste` is unmaintained. It is a compile-time proc-macro reached through libp2p.
- **Single verifier per network in the MVP.** Run verifiers at two or more organisations (roadmap).

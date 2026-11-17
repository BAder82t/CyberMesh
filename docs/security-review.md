# Internal security reviews

For v0.1.0, two independent internal reviews were run on the core crates on 2026-11-16:

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

## Third pass: Certificate Transparency monitoring (v0.2.0)

A third independent internal review covered the `ct-shard-scan` task type: the CT crate, the CT verifier, and the worker and coordinator changes. It found no CRITICAL issues. All findings below were fixed.

| Severity | Finding | Fix | Test or evidence |
|---|---|---|---|
| HIGH | Matches beyond the per-tile cap were dropped in (index, name) order, so a certificate with many decoy brand names could push a real lookalike out of the result. Truncation was not visible in reports. | At most 4 matches per certificate and 16 per tile, kept by priority (highest risk first). Truncated tiles are listed in verification records and in `ct report`. | `caps_keep_the_highest_risk_matches_and_commit_every_name`, `at_most_four_matches_per_entry` |
| HIGH | A legal maximal result (64 tiles × 256 matches) exceeded the 256 KiB message limit, so honest results for busy shards would be dropped. | 16 tiles per task, 16 matches per tile. The worst case is 181,928 bytes. | `worst_case_result_fits_the_envelope_limit` |
| MEDIUM | A worker could copy roots from the log's hash tiles and report no matches without parsing anything. Only a spot check of a tile with matches would catch it. | Each tile result commits to the count and digest of every extracted name. Spot checks compare whole tile results. The default is now 2 checks, the second drawn from tiles that report matches. | `spot_checks_favour_tiles_with_reported_matches`; names-digest assertion in the caps test |
| MEDIUM | The worker awaited the CT scan inside its event loop, so heartbeats, PAUSE/STOP and new tasks stalled for the whole scan, and throttling did not apply to it. | The scan runs on a background thread, one at a time. It waits while paused or throttled and stops on STOP, shutdown or task expiry. The result comes back over a channel. Domain tasks keep running meanwhile. | integration tests `ct_e2e` (3); local demo |
| MEDIUM | HTTP accepted non-200 responses (for example a redirect body) and hash tiles of the wrong length. A log whose data and hash tiles disagree would have honest workers faulted. | HTTP 200 only, exact hash tile length. A root mismatch is a fault only once the verifier's own scan matches the log. Otherwise the tile is recorded as log-inconsistent, nobody is faulted and the task is disputed. | `an_inconsistent_log_faults_nobody_and_is_disputed`, `a_root_mismatch_the_verifier_cannot_settle_is_not_verified` |
| MEDIUM | The coordinator finalised CT tasks with `block_in_place` on its event loop. Each finalisation may fetch several tiles (30 s timeout each). | Finalisation runs on blocking threads, at most 2 at a time. Records are applied through a channel, and `exit_when_done` waits for them. The start-up checkpoint fetch also moved off the loop. | integration tests; local demo |
| MEDIUM | The lookalike check computed a quadratic edit distance for every (name part, brand token) pair, which hostile CT names can make expensive. | Length-difference precheck (distance ≥ length difference) and the de-leeting hoisted out of the loop. Output is unchanged. | `golden_vectors` unchanged |
| MEDIUM | `x509-parser` was not pinned, yet it determines which names a CT scan extracts. Honest workers on different versions could disagree and be faulted. | Pinned to `=0.18.1` and recorded in `ENGINE_VERSION`. | engine version string |
| LOW | CT log URL validation rejected `[::1]` by mistake and accepted percent-encoding and IP literals over HTTPS. | Authority parsed properly. HTTPS needs a lowercase DNS host name; ports must be numeric; `%` and `\` are refused. | `ct_log_url_policy` |
| LOW | A node with an empty state directory accepted any valid, unexpired manifest, including an old one. | Optional `min_sequence` floor in the governance root. | `governance_root_floor_protects_a_fresh_node` |
| LOW | `ct scan` added the tile range without an overflow check. | `checked_add`. | — |
| LOW | Entries without a `leaf_index` extension were accepted, so entries were not bound to their position. | The extension is required (static-ct-api mandates it). A real Let's Encrypt tile still parses. | `parse_data_tile` tests; one-tile check against Willow 2027h1 |

## Fourth pass: independent verifiers (v0.2.0)

An independent internal review covered the multi-verifier change:
- the verifier node;
- the record identity binding;
- the release quorum;
- manifest `min_verifiers`.

It found no CRITICAL issues, and it confirmed that:
- record relabelling is refused;
- operators, not keys, are counted;
- the build is deterministic and cannot panic;
- a single verifier can neither list nor escalate an entry, apart from finding 1 below.

| Severity | Finding | Fix | Test or evidence |
|---|---|---|---|
| HIGH | A verifier lacking the task's engine or evidence still signed `Verified` warn records (`recomputed: false`). A colluding issuer could pin evidence the honest verifier lacks and borrow its signature for the quorum. | With a quorum of 2 or more, only recomputed records count. The verifier node reports such tasks as `tasks_incompatible`. | `only_recomputed_records_count_towards_a_quorum` |
| MEDIUM | The verifier inserted every result, even rejected junk, into its fail-closed replay cache. An authenticated peer could fill it and lock out new tasks. | Only accepted results, and only followed tasks, enter the cache. | code review |
| MEDIUM | The early-result buffer was bounded by count only (about 1 GiB of 256 KiB results), and late results for settled tasks were buffered. | Budgets of 1,024 results, 16 MiB and 32 per worker; settled tasks are remembered and their late results dropped. | `early_results_are_bounded_per_worker_and_in_bytes` |
| MEDIUM | Followed tasks and CT verifications were unbounded, and many deadlines in one tick could stall the event loop. | At most 1,024 tasks followed, 16 settled per tick, and 8 CT verifications running or queued. | code review |
| MEDIUM | Tasks were keyed by (id, attempt). A different task reusing the id, from another enrolled issuer, could take the real task's place. | Keyed by (id, attempt, task digest). Results are routed by the digest they answer. | code review |
| MEDIUM | `release build` ignored the governance root's `min_sequence`, so an older manifest with a weaker quorum could be supplied. The quorum is enforced only by builders. | The floor is honoured. Documented that co-signers must rebuild from records with the current manifest. | `docs/architecture.md` §3.4a |
| LOW | `min_verifiers` validation counted revoked verifier keys, and it rejected manifests without verifiers even at 1. | Only non-revoked operators are counted, and 1 is always accepted. | `min_verifiers_is_bounded_by_verifier_operators_and_omitted_when_one` |
| LOW | Evidence could cite only one supporting record when many sources were pinned, and every citation used the representative record's task id. | Supporting records are cited first, each with its own task id, and the total stays at 16 or fewer. | `evidence_cites_each_record_with_its_own_task_and_stays_within_limits` |
| LOW | The replay check on result payload digests never matched, because a different digest was inserted. | The same payload digest is inserted and checked. | code review |

Kept as is:
- **One bad record file aborts `release build`.** This is fail-closed on purpose: a signer should notice, not silently skip records.
- **Independent verifiers do not prove late equivocation.** This is on the roadmap.

## Fifth pass: record distribution over the network

An independent internal review covered the `records` topic, the record store and the exit logic. It found no CRITICAL issues. Its findings, fixed unless stated:

| Severity | Finding | Fix | Test or evidence |
|---|---|---|---|
| HIGH | One stored record that no longer verifies aborted every `release build`, for example a record from a since-revoked verifier, or from a verifier the signer's manifest does not know yet. | `release build` skips and names invalid files; `--strict` restores the old behaviour. Nodes re-check their store on every manifest update and remove records that no longer verify. | `records_must_name_their_actual_signer_and_its_operator`, `revoked_verifiers_records_are_removed_and_old_ones_pruned` |
| HIGH | The store was bounded by count only. One enrolled verifier could fill disk and memory and lock out honest records. | Byte and per-operator quotas; at most 2 records per operator and task; parsed records kept in memory only up to 4,096. | `rewrapped_records_are_stored_normalized_and_quotas_hold` |
| MEDIUM | A relay could re-wrap an honest record with junk signatures and store up to 256 KiB per record. | The store keeps only the record verifier's own valid signature. | `rewrapped_records_are_stored_normalized_and_quotas_hold` |
| MEDIUM | Records were never pruned, so the store eventually filled for good. | Pruned by age, every minute and on start. | `revoked_verifiers_records_are_removed_and_old_ones_pruned` |
| MEDIUM | Honest relays were penalised for local conditions: manifest lag, clock skew, a full quota, a disk error. | Peers are penalised only for provable forgery; everything else is ignored. | `stores_only_valid_records_of_other_verifiers` |
| MEDIUM | The exit wait counted records by task id only. Organisations' stores can differ, and a restart lost records awaiting re-publication. | Counts records for the same task digest. Own records are re-published after a restart. Documented that co-signers compare the releases' `inputs` when payloads differ. | `own_records_are_republished_after_a_restart` |
| LOW | Duplicates were fully verified before being recognised. | Cheap raw-digest check first. | code review |
| LOW | `flush` could hold the event loop for up to 1,024 publications, and duplicate detection matched an error string. | At most 32 publications per tick; a typed `NetError::Duplicate`. | code review |
| LOW | A node with no own records leaves without waiting. | Not changed: every settled task writes an own record, so this needs a failed write, which is logged. | — |

Residual risks:
- Records are readable by every allow-listed peer. They are audit material, not secrets.
- Records over 256 KiB are not distributed.
- The build-time manifest is authoritative.
- An operator can date its own record up to 300 s ahead and so make it its "latest".

## Sixth pass: CT checkpoint verification and tile-root proofs

An independent internal review covered the checkpoint verifier, the Merkle proofs and their integration. It found no CRITICAL or HIGH issues and could not forge a checkpoint or get a wrong tile root accepted. That was confirmed for every tree size up to 1,300 and for sizes with partial tiles at levels 0–3. Its findings, fixed unless stated:

| Severity | Finding | Fix | Test or evidence |
|---|---|---|---|
| MEDIUM | Withholding a tile's hash tiles, or replaying an older signed checkpoint, left that tile without a proven root. The verifier then trusted its own rescan, so a forged data tile could get honest workers faulted. | A tile without a proven root leaves the task `insufficient`, and such rescans are never evidence. Checkpoints older than an hour or dated in the future are refused. | `unanchored_tiles_leave_the_task_insufficient_and_fault_nobody`, `stale_or_future_checkpoints_are_refused` |
| MEDIUM | No fallback when a log deletes a partial hash tile after completing it, which static-ct-api allows. | The full tile is fetched and truncated to the signed width. | `missing_partial_tiles_fall_back_to_the_full_tile` |
| LOW | A wrong-length hash tile, such as a CDN error page, counted as a log contradiction. | Only a hash mismatch counts. A wrong length means unavailable. | code review |
| LOW | A malformed signature line under the pinned key name was skipped. | It rejects the note, as C2SP signed-note requires. | `rejects_unsigned_malformed_and_extended_notes` |
| LOW | The public mock-log key could be pinned for a real log by mistake. | Refused unless the log is a plain-HTTP loopback test log. | `ct_log_key_and_origin_policy` |
| LOW | The pinned key's point is not checked to be on the curve. | Not changed: an invalid point fails closed at verification. | — |

Residual risk: a log that signs different trees for different viewers (a split view) is not detected without witnesses (roadmap).

## Accepted or deferred (documented residual risk)

- **Manifest state on restart.** Fixed in v0.2.0: nodes persist the highest manifest sequence and digest they accepted, and the governance root can set a `min_sequence` floor for nodes without state.
- **Extension trust root.** The extension's trust root is bundled, so a revoked release key is removed only by shipping an extension update.
- **Synchronous analysis.** `assess_task` runs on the worker's async loop. It costs about 1 ms per 32-domain task.
- **Gossipsub peer scoring is not enabled.** Bad messages are rejected but the sender's mesh score is not reduced.
- **`RUSTSEC-2024-0436`.** `paste` is unmaintained. It is a compile-time proc-macro reached through libp2p.
- **Quorum enforced by builders only.** Browsers never see records, so they cannot check `min_verifiers`. Co-signers must rebuild rather than sign a payload someone else built.
- **Verifier quorum is opt-in.** Independent verifiers and the manifest's `min_verifiers` exist since v0.2.0. With `min_verifiers = 1`, the default for compatibility, a single verifier is still trusted as in v0.1. Networks should set 2 or more and run at least one more verifier than that.
- **Late CT equivocation during finalisation.** CT tasks are finalised in the background. A second, conflicting result that arrives in that window (usually seconds) is ignored rather than recorded as provable equivocation. Results that arrive before or after the window are handled as for domain tasks.

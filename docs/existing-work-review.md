# Existing work review: owner repositories, prior art and dataset licensing

| | |
|---|---|
| Date | 2026-11-16 |
| Scope | Read-only review to inform the CyberMesh MVP. It does not change the MVP design. |
| Status | Research note. Licence statements summarise published terms as read on the date above; they are not legal advice. |

## Contents

1. [Scope and method](#1-scope-and-method)
2. [Summary of findings](#2-summary-of-findings)
3. [Reuse decisions at a glance](#3-reuse-decisions-at-a-glance)
4. [Owner repositories](#4-owner-repositories)
5. [Format alignment checklist for CyberMesh](#5-format-alignment-checklist-for-cybermesh)
6. [Prior art](#6-prior-art)
7. [How CyberMesh differs from existing threat-sharing systems](#7-how-cybermesh-differs-from-existing-threat-sharing-systems)
8. [Dataset licensing and access (November 2026)](#8-dataset-licensing-and-access-november-2026)
9. [Open questions](#9-open-questions)
10. [References](#10-references)

---

## 1. Scope and method

**Repositories reviewed** (public default branch, shallow clone, read-only):

| Repository | Default branch | Commit reviewed | Commit date |
|---|---|---|---|
| [BAder82t/Encompute](https://github.com/BAder82t/Encompute) | `main` | `82ccc60a99ae4c3dc5596c47ccf85edc49b539a0` | 2026-10-19 |
| [BAder82t/regaudit-fhe](https://github.com/BAder82t/regaudit-fhe) | `master` | `bd524fbdcb9eb77af97812782083dc551d3653eb` | 2026-11-16 |
| [BAder82t/fhe-oracle-oss](https://github.com/BAder82t/fhe-oracle-oss) | `main` | `6506828533e89072a96f5ef4b30ec13ca4a9a616` | 2026-10-07 |
| [BAder82t/fhe-attack-replay](https://github.com/BAder82t/fhe-attack-replay) | `main` | `1f31ba4053e020d3ed73d55256cfa21817e85d4a` | 2026-05-01 |
| [BAder82t/verify-action](https://github.com/BAder82t/verify-action) | `main` | `ce94f8210c5206a18bd009c2bebc350f94edc3f8` | 2026-10-07 |

File paths in section 4 are relative to each repository root at the commit above. Local working copies under `~/dev` were not used, because they may be on other branches.

**Prior art** was checked against primary sources (specifications, project documentation, source repositories). **Dataset terms** were read from each provider's current pages, and public download URLs were checked with HTTP `HEAD` requests on 2026-11-16. No feed contents were downloaded and no listed malicious URL was visited.

**Out of scope for the MVP:** fully homomorphic encryption (FHE), secure aggregation, differential privacy and trusted-execution key release. Four of the five repositories are FHE-centred. Their FHE functionality is described only to explain why it is not reused. CyberMesh's inputs (domain names, pinned public feed snapshots) are not confidential between participants, so the MVP has no computation that needs encryption.

---

## 2. Summary of findings

1. **No code from the five repositories should be copied into CyberMesh.** Three are AGPL-3.0 (Encompute is AGPL-3.0-only; regaudit-fhe and fhe-oracle-oss are AGPL-3.0-or-later), and AGPL code cannot be included in an Apache-2.0 project without a separate grant from the copyright holder. verify-action is "All rights reserved". The only Apache-2.0 repository (fhe-attack-replay) is Python and FHE-specific, so there is no code worth porting. The useful material is design patterns, which can be reimplemented. The pieces worth having are small: canonical JSON is about 60 lines and the mutation tester about 120.
2. **Encompute is the most relevant source.** It is in Rust and already contains, on its unreleased `main` branch, close analogues of several CyberMesh components:
   - Ed25519 signing with per-object domain separation
   - integer-only canonical JSON
   - an RFC 6962 Merkle log with signed checkpoints, witness countersignatures, equivocation and rollback proofs
   - a signed state anchor that refuses rollback
   - quorum rules that count distinct people, not signatures
   - a field-mutation adversarial test harness
3. **regaudit-fhe is the best model for the verifier's contract.** The verifier returns a fail-closed verdict (`TRUSTED` / `SELF_SIGNED_ONLY` / `INVALID`) with machine-readable reason codes and exit codes. Trust anchors are always supplied by the verifier, never taken from the artefact. Golden test vectors are published per release.
4. **fhe-attack-replay and fhe-oracle-oss supply testing patterns**, not code: a registry of named attack scenarios with honest status semantics and strict CI exit codes, and differential testing with seeded reproduction and shrinking.
5. **Encompute and regaudit-fhe supply CI and release patterns:** actions pinned by commit SHA, `cargo-deny` licence allow-lists, SBOMs, Sigstore keyless signing, build provenance attestations, `SOURCE_DATE_EPOCH`, and a digest re-check between build and publish jobs. verify-action adds an idea worth reimplementing: tests that fail if the repository's own workflows stop pinning SHAs.
6. **Dataset access changed in October 2026.** abuse.ch retired keyless URLhaus and ThreatFox downloads (HTTP 410). Exports now require a free Auth-Key in the URL path. The current abuse.ch terms (last updated 2026-10-21) name CC0 only for Feodo Tracker, SSL Blacklist and YARAify. URLhaus and ThreatFox data carry no open licence, and commercial use may require a Spamhaus subscription. **None of the phishing or malware feeds reviewed grants a clear right to redistribute their data in a public Apache-2.0 repository.** Majestic Million (CC BY 3.0) is the only ranking list with an explicit open licence.
7. **Licensing also limits what CyberMesh can publish.** If a `block` verdict requires corroboration from a reference feed, then publishing the block list may amount to redistributing that feed's data. This needs a decision before any non-CC0 feed is used operationally (see [section 9](#9-open-questions)).

---

## 3. Reuse decisions at a glance

Decision values: **Reuse code**, **Adopt pattern** (reimplement from the documented design; copy no code), **Not applicable**.

| # | Pattern | Source (repository: path) | Decision | Reason |
|---|---|---|---|---|
| 1 | Per-object domain separation for hashes and signatures | Encompute: `crates/encompute-verification/src/hash.rs`; regaudit-fhe: `src/regaudit_fhe/report_v2.py` (`SIGN_DOMAIN`) | Adopt pattern | AGPL. In CyberMesh, DSSE `payloadType` provides this in a standard form. |
| 2 | Integer-only canonical JSON (sorted keys, no floats, no whitespace) | Encompute: `crates/encompute-verification/src/canonical.rs` | Adopt pattern | AGPL-3.0-only. About 60 lines to reimplement, or use `serde_jcs` (MIT OR Apache-2.0) with an integer-only check. |
| 3 | Ed25519 `verify_strict`; key ID = SHA-256(domain ‖ 0x00 ‖ public key) | Encompute: `crates/encompute-verification/src/identity.rs` | Adopt pattern | Uses `ed25519-dalek` (BSD-3-Clause) directly, so there is nothing to copy. |
| 4 | Strict parsing: `deny_unknown_fields`, size caps, canonical base64 and lowercase hex | Encompute: `crates/encompute-verification/src/receipt.rs`; regaudit-fhe: `src/regaudit_fhe/canonical.py` (`decode_canonical_b64`) | Adopt pattern | AGPL; trivial to reimplement. |
| 5 | Trust anchors come from the verifier, never from the artefact | regaudit-fhe: `src/regaudit_fhe/trust.py`, `README.md`; Encompute: `crates/encompute-trust/src/bundle.rs` (`Pins`) | Adopt pattern | Matches the governance-signed trust manifest. |
| 6 | Fail-closed verdicts with reason codes and documented exit codes | regaudit-fhe: `src/regaudit_fhe/verification.py`, `docs/TRUST_SPEC.md` §8; Encompute: `crates/encompute-trust/src/governance.rs` | Adopt pattern | Gives the extension and CLI a stable, testable contract. |
| 7 | RFC 6962 log: inclusion and consistency proofs, signed checkpoints, witness cosignatures, equivocation and rollback proofs | Encompute: `crates/encompute-trust/src/govlog.rs` (unreleased, `main` only) | Adopt pattern | AGPL and unreleased. Consider C2SP checkpoint formats and `ct-merkle` (MIT/Apache-2.0). |
| 8 | State anchor kept outside the database; refuse to start when behind it | Encompute: `crates/encompute-control/src/anchor.rs` | Adopt pattern | Applies to the publisher's sequence counter and the extension's high-water mark. |
| 9 | Quorum counts distinct principals, not signatures or accounts | Encompute: `crates/encompute-control/src/ops/jobs.rs` (`job_quorums`), `crates/encompute-control/tests/governed_jobs.rs` | Adopt pattern | Same rule as "≥3 distinct operators, not peer IDs" and "k-of-n org signers". |
| 10 | Revocation heads; retired and compromised keys are different states | Encompute: `govlog.rs` (`RevocationHead`); regaudit-fhe: `docs/TRUST_SPEC.md` §4, `docs/proposals/revocation-list.v1/` (experimental) | Adopt pattern | Design input for trust-manifest key revocation. Not production code. |
| 11 | Field-mutation tests: alter every field and require the verifier to reject | Encompute: `crates/encompute-assurance/src/mutate.rs` | Adopt pattern | About 120 lines; apply to every signed CyberMesh object. |
| 12 | `cargo-fuzz` targets for every parser | Encompute: `fuzz/fuzz_targets/*.rs` | Adopt pattern | Envelope, manifest, task, result and release parsers. |
| 13 | Attack-scenario registry with honest statuses and strict CI exit codes | fhe-attack-replay: `src/fhe_attack_replay/attacks/base.py`, `docs/status-semantics.md` | Adopt pattern | Apache-2.0 would allow reuse, but the code is Python and FHE-specific. |
| 14 | Differential testing with seeded reproduction, shrinking and a JSONL replay log | fhe-oracle-oss: `fhe_oracle/differential.py`, `fhe_oracle/evallog.py`, `fhe_oracle/check.py` | Adopt pattern | AGPL, Python. Use for Rust-vs-JS verification and recompute checks. |
| 15 | Golden test vectors frozen per release | regaudit-fhe: `tests/vectors/`, `tests/test_report_v2_vectors.py`, `tests/test_published_0_1_0_vectors.py` | Adopt pattern | Essential for Rust ↔ WebCrypto agreement. |
| 16 | Release supply chain: SHA-pinned actions, `cargo-deny`, SBOM, cosign keyless signing, build provenance, `SOURCE_DATE_EPOCH` | Encompute: `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `deny.toml`, `docs/verify-release.md`; regaudit-fhe: `.github/workflows/pypi-release.yml` | Adopt pattern | Write CyberMesh's own configuration; these files are in AGPL repositories. |
| 17 | Tests asserting the repository's own workflows pin SHAs, use `contents: read` and refuse `pull_request_target` | verify-action: `test/supply-chain.test.mjs`, `SECURITY.md` | Adopt pattern (idea only) | All rights reserved; do not copy. |
| 18 | FHE backends (CKKS/BFV/TFHE), secure aggregation, differential privacy | Encompute: `encompute-ckks`, `encompute-openfhe*`, `encompute-secagg`, `encompute-privacy`; regaudit-fhe: `src/regaudit_fhe/fhe/`, `dp.py`; fhe-oracle-oss; fhe-attack-replay | Not applicable | FHE is out of MVP scope; MVP inputs are not confidential. |
| 19 | TEE attestation and attested key release | Encompute: `encompute-attestation`, `encompute-keybroker` | Not applicable | Out of MVP scope. |
| 20 | Encompute control plane (PostgreSQL, OpenBao) | Encompute: `crates/encompute-control/` | Not applicable | Far heavier than CyberMesh needs; AGPL. |
| 21 | Any verbatim code reuse | All five | Not applicable | Licence (AGPL / all rights reserved) or language and domain mismatch (fhe-attack-replay). |

---

## 4. Owner repositories

### 4.1 Licence verification

All five repositories have a `LICENSE` file at the root. The GitHub API now reports a detected licence for each one (`gh repo view --json licenseInfo`, checked 2026-11-16). This differs from the earlier observation that `gh` reported none.

| Repository | `LICENSE` file | Other licence files | Package metadata | Outbound compatible with Apache-2.0? |
|---|---|---|---|---|
| Encompute | AGPL-3.0 text (added 2026-09-24) | `LICENSING.md` (AGPL-3.0-**only** plus commercial licence), `THIRD_PARTY_NOTICES.md` | `Cargo.toml`: `license = "AGPL-3.0-only"`; `pyproject.toml`: AGPL-3.0-only | **No** |
| regaudit-fhe | AGPL-3.0 text | `LICENSING.md`, `LICENSE-COMMERCIAL.md` (AGPL-3.0-**or-later** plus paid VaultBytes Commercial License) | `pyproject.toml`: `AGPL-3.0-or-later` | **No** |
| fhe-oracle-oss | AGPL-3.0 text | `NOTICE`: "Copyright (C) 2026 Bader Alissaei / VaultBytes Innovations Ltd … AGPL-3.0-or-later" | `pyproject.toml`: `AGPL-3.0-or-later`; source headers `SPDX-License-Identifier: AGPL-3.0-or-later` | **No** |
| fhe-attack-replay | Apache-2.0 text | `NOTICE` (attack papers cited; states no upstream proof-of-concept source is redistributed) | `pyproject.toml`: `Apache-2.0`; source headers `SPDX-License-Identifier: Apache-2.0` | **Yes** (preserve `NOTICE`) |
| verify-action | Proprietary: "Copyright (c) 2026 VaultBytes Innovations Ltd. All rights reserved … No licence is granted to copy, modify, redistribute or sublicense it" (added 2026-10-07) | none | none (no `package.json`) | **No.** Not open source. |

**Relicensing.** The copyright notices name Bader Alissaei and/or VaultBytes Innovations Ltd. Encompute's `LICENSING.md` says outside contributions cannot be merged without a CLA, and regaudit-fhe's says outside contributions are not accepted. The rights holder could therefore, in principle, grant specific files to CyberMesh under Apache-2.0. That is the rights holder's decision (possibly the company rather than the individual), and this review does not assume it. Because the valuable parts are small and well documented, clean reimplementation is the simpler path.

Linking an AGPL crate (for example `encompute-verification`) into CyberMesh binaries would also subject the combined distributed work to the AGPL. That is a further reason not to depend on these crates.

### 4.2 Encompute

| | |
|---|---|
| **Purpose** | "A compiler and trust runtime for confidential AI and cross-organization computation" (`README.md`). Python programs mark secret values; the evaluator computes on FHE ciphertexts. Around this sit purpose-bound authorisation, secure aggregation, differential privacy, attested key release, a trust graph, lineage and signed evidence. |
| **Language** | Rust (26 workspace crates, about 191k lines including tests) with a Python SDK (`crates/encompute-py`, maturin) and C++ OpenFHE FFI. `unsafe_code = "deny"` at workspace level. |
| **Licence** | AGPL-3.0-only plus commercial licence. |
| **Maturity signals** | 1,399 `#[test]` functions. CI workflows: `ci.yml` (fmt, clippy `-D warnings`, tests, assurance suite, `cargo deny`), nightly `assurance.yml`, `conformance.yml`, `fuzz.yml` (19 fuzz targets), `release.yml`. Five releases; latest **v0.3.3** (2026-10-18), with Sigstore bundles, CycloneDX SBOMs and build provenance for every artefact. Advisory GHSA-rm8x-939m-3fgp (privacy-budget accounting and **governance-state rollback protection**) was fixed in 0.3.3. `main` is **0.4.0-rc.1, unreleased**; the README says its control-plane security work "is not production-ready". The nightly `assurance` run on `main` failed on 2026-11-16. Repository created 2026-09-24. |
| **Release vs `main`** | `crates/encompute-trust/src/govlog.rs`, `bundle.rs` and `governance.rs` **do not exist at v0.3.3**; they are `main`-only. `canonical.rs`, `receipt.rs` and `anchor.rs` exist at v0.3.3 (file presence checked, contents not compared). |

**Relevant patterns** (all **Adopt pattern** unless noted):

- **(a) Signatures and verification**
  - `crates/encompute-verification/src/hash.rs`: domain-separated SHA-256, `SHA256(domain || 0x00 || bytes)`, with one domain constant per object type (`encompute.execution-receipt.v1`, `encompute.evaluator.v1`, …), "so one can never be read as another".
  - `crates/encompute-verification/src/identity.rs`: Ed25519 via `ed25519-dalek` 2.2. Verification uses `verify_strict`, which rejects weak keys and non-canonical signatures. Evaluator IDs are derived from the public key under their own domain.
  - `crates/encompute-verification/src/receipt.rs`: signed receipt with `deny_unknown_fields`, `MAX_RECEIPT_BYTES = 16 KiB`, an explicit version, and the text "A receipt is a signed claim, not a proof".
  - Note: Encompute signs the 32-byte **domain-separated digest**, not the message. DSSE signs `PAE(payloadType, payload)` directly. Do not mix these conventions in CyberMesh; follow DSSE.
- **(b) Privacy-preserving computation**
  - `encompute-ckks`, `encompute-openfhe*`, `encompute-tfhe*`, `encompute-secagg`, `encompute-privacy`, `encompute-attestation`, `encompute-keybroker`. **Not applicable** (FHE, secure aggregation, DP and TEE key release are out of MVP scope).
- **(c) Security testing and adversarial simulation**
  - `crates/encompute-assurance/src/lib.rs`: "for every documented security invariant, a check that tries to break it through the public interfaces", at PR and nightly scale.
  - `crates/encompute-assurance/src/mutate.rs`: mutates every JSON leaf, drops every optional field and pops every array, then requires the verifier to reject each variant.
  - `fuzz/fuzz_targets/`: 19 targets, including `receipt_parse.rs`, `message_envelope.rs`, `trust_bundle.rs` and `job_grant.rs`.
- **(d) Signed evidence formats**
  - `crates/encompute-verification/src/canonical.rs`: canonical JSON with keys sorted by UTF-8 bytes, no whitespace and **integers only** (floats, NaN and infinities refused). It is identical to RFC 8785 for that subset, and the key order is imposed so that serde's `preserve_order` cannot change it.
  - `crates/encompute-trust/src/bundle.rs`: an offline evidence bundle in which each section's digest sits in a manifest. The file must be exactly the canonical encoding of what it parses to. "Signatures are attribution": they add no trust; pins do.
- **(e) Decentralised trust governance**
  - `crates/encompute-trust/src/govlog.rs` (`main` only):
    - RFC 6962 leaf and node hashing, with inclusion and consistency proofs
    - `ProjectCheckpoint`, signed by the control plane
    - `CheckpointWitness`, a countersignature by each member organisation after checking the new checkpoint extends the one it saw before
    - `EquivocationProof` (same size with different roots, or an inconsistent consistency proof)
    - `RollbackProof`
    - `RevocationHead`, an owner's signed statement of its revocations, so an exported bundle cannot silently omit one
  - `crates/encompute-control/src/anchor.rs`: a signed anchor of the audit root and log head kept **outside** the database. "Restoring an older database backup rewinds the database, not the anchor"; the service refuses to start when it is behind the anchor.
  - Quorums count distinct people: the test `a_four_eyes_job_runs_only_after_two_distinct_people_of_the_owner_approve_it` (`crates/encompute-control/tests/governed_jobs.rs`) asserts that "a service account and one person approving twice never make a quorum".
  - `crates/encompute-trust/src/governance.rs`: verdict rows are NOT PRESENT, UNCHECKED, FAILED or SATISFIED. "A key that is not pinned is UNCHECKED, never a pass."
- **(f) Automated verification workflows**
  - `.github/workflows/ci.yml`: every third-party action pinned to a 40-character SHA, `cargo deny check advisories bans licenses sources`, and `scripts/release/check-pins.sh`.
  - `.github/workflows/release.yml`: `SOURCE_DATE_EPOCH`, CycloneDX SBOMs, `cosign sign`/`attest` (keyless, `id-token: write`) and `actions/attest-build-provenance`.
  - `deny.toml`: a permissive-only licence allow-list.
  - `docs/verify-release.md`: a three-step consumer verification (checksums, cosign identity regex bound to the release workflow on a tag, GitHub attestations).

### 4.3 regaudit-fhe

| | |
|---|---|
| **Purpose** | Six AI-audit calculations (fairness, provenance, concordance, calibration, drift, disagreement) whose results go into an Ed25519-signed report that a regulator verifies against its own trust store. CKKS (TenSEAL, experimental OpenFHE) is an optional backend. The README states that the same process currently holds the key and sees inputs and results. |
| **Language** | Python (about 16k source lines), plus an experimental local "Evidence Verification Portal" (HTML/JS) and a Swift component. |
| **Licence** | AGPL-3.0-or-later plus VaultBytes Commercial License. |
| **Maturity signals** | 1,799 test functions. CI: pytest on Linux py3.10 to 3.13 and macOS, an 80% coverage gate (about 89% reported in `docs/STATUS.md`), mypy, ruff, bandit, CodeQL, docs build. Release workflows: `release-build.yml`, a credential-free `release-rehearsal.yml`, and `pypi-release.yml` with PyPI trusted publishing and Sigstore. Eleven releases; latest **v0.2.1** (2026-11-01) on PyPI. `docs/STATUS.md`: "reference implementation … verification core is a candidate … not had any independent external security audit". Four advisories for 0.2.1 (issuer attribution, replay protection, trust-store and replay-file permissions). The revocation protocol (`docs/proposals/revocation-list.v1/`) is "EXPERIMENTAL, off by default" and is not in a release. |

**Relevant patterns:**

- **(a) Signatures and verification**
  - `src/regaudit_fhe/report_v2.py`: the signing input is `SIGN_DOMAIN || canonical_bytes(signed_body)` with `SIGN_DOMAIN = b"regaudit-fhe/report/v2/sign\x00"`, and the receipt carries `signature_alg`, the signature and an embedded public key.
  - The README is explicit that an embedded key proves nothing: "Get the public key out of band, never from a report." Test file `tests/test_valid_signature_is_not_trusted_signer.py` pins this rule. **Adopt pattern.**
- **(b) Privacy-preserving computation**
  - `src/regaudit_fhe/fhe/`, `src/regaudit_fhe/dp.py`. **Not applicable.**
- **(c) Security testing**
  - Hostile-input suites: `tests/test_envelope_robustness.py`, `tests/test_input_limit_bypass.py`, `tests/test_revocation_hostile_sequences.py`, `tests/test_server_resource_bounds.py`.
  - Frozen vectors: `tests/vectors/report_v2/`, `tests/vectors/published_0_1_0/` and `tests/test_published_0_1_0_vectors.py`, which keep old signatures verifying. **Adopt pattern.**
- **(d) Signed evidence formats**
  - `src/regaudit_fhe/canonical.py`: a strict parser that refuses duplicate keys, NaN, a BOM, invalid UTF-8, lone surrogates, trailing data and excess depth or size. It also has canonical base64 decoding (re-encoding must reproduce the input).
  - **Caveat:** it accepts floats and formats them with Python's `repr`. The module itself records that "a non-Python verifier would need RFC 8785 number formatting". CyberMesh verifies in both Rust and JavaScript, so it should follow Encompute's integer-only rule instead.
  - Schemas: `schemas/envelope.v2.schema.json`. **Adopt pattern** (strict parsing); **do not adopt** float handling.
- **(e) Trust governance**
  - `docs/TRUST_SPEC.md` covers key states (§4.1), retirement versus compromise with an unknown boundary (§4.3 to §4.4), offline verification and completeness of trust history (§4.6), RFC 3161 time evidence with "no default roots" (§5), replay state (§6), and the response contract and reason codes (§8).
  - `src/regaudit_fhe/verification.py` returns `TRUSTED`, `SELF_SIGNED_ONLY` or `INVALID`, with codes such as `ISSUER_UNKNOWN`, `KEY_REVOKED`, `SIGNED_AFTER_COMPROMISE`, `REPORT_TOO_OLD`, `REPLAY_DETECTED` and `PIN_MISMATCH`. CLI exit codes: 0 accepted, 1 refused, 2 usage, 3 resource unusable.
  - **Adopt pattern** for the CyberMesh verifier and extension result contract.
- **(f) Workflows**
  - `.github/workflows/pypi-release.yml` re-checks the wheel and sdist SHA-256 between the build, Sigstore and publish jobs.
  - `.github/workflows/release-rehearsal.yml` runs the release build on PRs with no credentials.
  - `.github/dependabot.yml`.
  - **Adopt pattern:** build the threat-list release once, then have every signer verify the same digest before signing.

### 4.4 fhe-oracle-oss

| | |
|---|---|
| **Purpose** | "Adversarial precision testing for Fully Homomorphic Encryption." CMA-ES search for inputs where an encrypted program diverges from its plaintext reference, then shrinking those inputs into reproducible tests. |
| **Language** | Python (about 6.6k lines), with a small Go helper. |
| **Licence** | AGPL-3.0-or-later. A `LICENSE` file exists, matching the repository description. |
| **Maturity signals** | 443 test functions. CI: pytest on a Python matrix, ruff, mypy, and native TenSEAL integration tests. One GitHub release, **v0.7.0** (2026-09-15), on PyPI; release notes: "The package remains Alpha; PASS is a bounded empirical result, not a proof." Last push 2026-10-07. |

**Relevant patterns:**

- **(c) Security testing**
  - `fhe_oracle/differential.py` searches for disagreement between two independent implementations.
  - `fhe_oracle/check.py` chains search, shrink and report.
  - `fhe_oracle/evallog.py` keeps a JSON Lines evaluation log "for audit and replay".
  - `fhe_oracle/seeds.py` uses seeded corner and random initialisation.
  - **Adopt pattern** for CyberMesh differential tests:
    - the Rust engine against an independent reference implementation of the lexical rules
    - the Rust verifier against the extension's WebCrypto verifier, on generated envelopes
    - seeded generation of domain names (IDN, punycode, mixed scripts, long labels), with failures shrunk to a minimal domain and frozen as regression vectors
- (a), (b), (d), (e), (f): nothing beyond standard CI. (b) is **Not applicable**.

### 4.5 fhe-attack-replay

| | |
|---|---|
| **Purpose** | "Unified attack-replay regression harness for FHE libraries (SEAL, OpenFHE, Lattigo, tfhe-rs)." It replays published attacks such as IND-CPA-D (ePrint 2024/127) against a `(library, params)` target. Also a GitHub Action (`action.yml`) that emits a JSON report and an SVG badge. |
| **Language** | Python (about 4.6k lines), with Go (`vendor/lattigo-helper`) and Rust (`vendor/tfhe-rs-helper`) helper binaries. |
| **Licence** | Apache-2.0, with a `NOTICE` file. Licence-compatible with CyberMesh. |
| **Maturity signals** | 274 test functions. CI: ruff, pytest with coverage, Go helper tests. PyPI trusted publishing. Seven releases; latest **v0.3.1** (2026-05-01). README: "**Alpha**". No pushes since 2026-05-01. Workflows pin actions by tag (`@v4`), not SHA. |

**Relevant patterns:**

- **(c) Security testing**
  - `src/fhe_attack_replay/attacks/base.py`: an `Attack` base class with `id`, `citation` and `intent` (`REPLAY` / `RISK_CHECK` / `ARTIFACT_CHECK`). `AttackStatus` takes the values `VULNERABLE`, `SAFE`, `SKIPPED`, `NOT_IMPLEMENTED` and `ERROR`.
  - `src/fhe_attack_replay/registry.py`: the scenario registry.
  - `docs/status-semantics.md`: the worst status wins, and exit codes are distinct (2 vulnerable, 3 error, 4 not implemented, 5 all skipped). Its stated principle: "silent green CI for runs that did not actually exercise an attack is a footgun".
  - **Adopt pattern** for a CyberMesh `adversarial-sim` crate. Candidate scenarios:
    - Sybil peers under one operator (must not count toward ≥3 operators)
    - colluding operators returning a wrong result
    - an equivocating issuer or publisher (two releases with the same sequence)
    - a replayed task or result
    - a stale or rolled-back release
    - a key substituted inside an envelope
    - a peer not in the manifest publishing on gossipsub
    - oversized or malformed envelopes
    - an expired manifest
  - The code is licence-compatible, but it is Python and FHE-specific. **Reuse code: no.**
- (f) **Workflows:** `action.yml` and its `allow-not-implemented`, `allow-skipped` and `min-coverage` inputs show how to make CI strict by default. **Adopt pattern.**
- (a), (b), (d), (e): (b) is **Not applicable**; the others are absent.

### 4.6 verify-action

| | |
|---|---|
| **Purpose** | Client GitHub Action for "VaultBytes Verify", a hosted service (private pilot, token required) that checks FHE library commits against a high-precision reference. |
| **Language** | JavaScript (Node ≥ 18 ESM; about 560 source lines), composite action. |
| **Licence** | **All rights reserved** (VaultBytes Innovations Ltd). Not open source. |
| **Maturity signals** | 41 tests, including `test/supply-chain.test.mjs`, `test/hostile.mjs` and a stub API. One release, v0.2.1 (2026-10-07), with a SHA-256 file and a build provenance attestation. Dependabot is active. The service itself is not public. |

**Relevant patterns (ideas only; do not copy):**

- (f) The final `action.yml` step fails anything that is not an explicit pass, including a crash that produced no decision.
- (f) `test/supply-chain.test.mjs` asserts that every workflow has `permissions: contents: read`, pins third-party actions to SHAs and avoids `pull_request_target`. It also asserts that the action refuses `pull_request_target` and `workflow_run` before it reads the token.
- (f) `SECURITY.md`: pin by commit SHA; enable immutable releases and a tag ruleset; make signed annotated tags mandatory (the release workflow refuses lightweight tags).
- (a) to (e): (b) is **Not applicable**; the others are absent.

---

## 5. Format alignment checklist for CyberMesh

These are concrete recommendations that come from the review. None of them changes the agreed design.

1. **Envelope.** Use DSSE exactly as specified (`payload`, `payloadType`, `signatures[{keyid, sig}]`; signature over `PAE("DSSEv1", …)`). Give each object type its own lowercase, versioned `payloadType`, for example `application/vnd.cybermesh.domain-risk-result.v1+json`. This does the job of Encompute's per-type domain constants (`crates/encompute-verification/src/hash.rs`). `keyid` is a hint only; the DSSE specification says it "MUST NOT be used for security decisions". Authorisation comes from the trust manifest's key-to-operator mapping.
2. **Canonical payload JSON.**
   - Follow Encompute's rule (`crates/encompute-verification/src/canonical.rs`): keys sorted by UTF-8 bytes, no whitespace, integers only.
   - Express risk scores as integers (basis points or per-mille) and timestamps as integer seconds or RFC 3339 strings.
   - Verifiers check the signature over the received bytes and then parse strictly; they never re-serialise to verify.
   - Release digests are computed over canonical bytes, so any independent rebuild must produce the same bytes.
3. **Ed25519 agreement between Rust and the browser.**
   - Use `verify_strict` in Rust, as Encompute's `identity.rs` does. `ed25519-dalek` 3.0.0 is now on crates.io; Encompute pins 2.2.
   - Ed25519 implementations disagree on edge cases (small-order keys, non-canonical encodings; see "Taming the many EdDSAs").
   - Reject small-order and non-canonical public keys when the trust manifest is loaded, in both Rust and the extension.
   - Ship shared edge-case vectors that both verifiers must agree on.
   - Web Crypto Ed25519 is enabled by default from Chrome 137.
4. **Strict parsing everywhere.** Use `#[serde(deny_unknown_fields)]`, a byte cap per object type (Encompute uses 16 KiB for receipts), lowercase hex and canonical base64 only (regaudit-fhe `decode_canonical_b64`; C2SP signed-note uses the same rule), and explicit `version` fields.
5. **Verifier contract.** Return a tri-state result with reason codes, modelled on regaudit-fhe (`TRUSTED` / `SELF_SIGNED_ONLY` / `INVALID` with `blocking_reasons`) and Encompute's rule that "not pinned is UNCHECKED, never a pass". Document the CLI exit codes. The extension shows `block` only on a fully verified release whose entry carries independent feed corroboration.
6. **Distinct-operator counting.** Count organisations from the trust manifest. A single operator with several peer IDs, keys or workers counts once, by analogy with Encompute's "one person approving twice never make[s] a quorum" test. Apply the same rule to the k-of-n release signers.
7. **Release log.** Hash leaves and nodes as RFC 6962 does (0x00 and 0x01 prefixes), with inclusion and consistency proofs. For checkpoints and witness cosignatures, consider the C2SP `tlog-checkpoint`, `signed-note` and `tlog-cosignature` formats rather than a bespoke format, so existing witness tooling can be used. Keep Encompute's `EquivocationProof` and `RollbackProof` ideas as offline-checkable objects.
8. **Rollback protection.**
   - The publisher keeps a signed sequence and log-size anchor outside its database and refuses to issue a release that does not extend it (Encompute `anchor.rs`).
   - The extension stores the highest verified `(sequence, log size, root)` and rejects lower sequences or inconsistent roots.
   - Encompute's own advisory GHSA-rm8x-939m-3fgp shows this is easy to get wrong.
9. **Testing.**
   - Field-mutation tests on every signed type (Encompute `mutate.rs`).
   - `cargo-fuzz` targets per parser.
   - An adversarial-scenario registry with strict exit codes (fhe-attack-replay).
   - Differential Rust ↔ JS tests (fhe-oracle-oss).
   - Frozen golden vectors per release (regaudit-fhe `tests/vectors/`).
10. **CI and release.**
    - Pin actions by SHA, set `permissions: contents: read` by default, and run `cargo deny` with a permissive licence allow-list.
    - Produce an SBOM, sign software artefacts with keyless cosign, and add `attest-build-provenance`.
    - Add a self-test that the workflows keep these properties.
    - Software release signing (Sigstore) is separate from threat-list signing (long-lived org keys, k-of-n).

---

## 6. Prior art

### 6.1 MISP

**What it is.** MISP is an open-source threat-intelligence sharing platform (AGPL-3.0). Data is organised as events containing attributes and objects. It provides taxonomies (for example TLP), galaxies, correlation, sightings and a decay model.

Distribution is controlled per event or attribute at five levels (your organisation only; this community; connected communities; all communities; sharing group). Instances synchronise by push and pull over authenticated API keys. MISP also consumes and produces feeds (MISP JSON, CSV, free text). Newer versions support **protected events**, whose updates must be signed by a listed instance key.

**misp-warninglists** is a separately maintained set of known-benign lists (Majestic, Cisco top lists, CrUX, cloud IP ranges, URL shorteners and others) used to flag likely false positives.

**How CyberMesh differs.**
- MISP is a general-purpose, analyst-driven sharing platform: humans create events, and trust is between instance administrators. CyberMesh is a narrow pipeline: an issuer creates tasks, workers compute deterministically, a verifier aggregates, and the output is a multi-signed, expiring release that end-user browsers verify offline.
- MISP does not provide end-to-end signatures verifiable by a browser, a k-of-n release quorum or a public append-only release log. MISP does provide far richer data models, a mature community and broad integrations.
- CyberMesh is not a replacement for MISP.

**What we borrow.**
- Export CyberMesh releases as a MISP feed (and/or STIX 2.1) for interoperability.
- Use TLP-style distribution labels if non-public data is ever added.
- Treat warninglists as the model for a benign-domain suppression stage. Check each warninglist's upstream licence before shipping it; the repository has no detected licence.

### 6.2 URLhaus (abuse.ch)

**What it is.** A community platform, operated by abuse.ch with Spamhaus, for sharing URLs used for **malware distribution**. Its focus is malware, not phishing. It offers an API and file exports (CSV/JSON dumps, hostfile, RPZ, Suricata rules, MISP events).

Since October 2026, exports require a free abuse.ch Auth-Key embedded in the URL (`https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv`). The old `https://urlhaus.abuse.ch/downloads/...` paths return HTTP 410. Commercial use may require a Spamhaus subscription. Details are in [section 8](#8-dataset-licensing-and-access-november-2026).

**How CyberMesh differs.** URLhaus is a curated, centrally operated submission and triage service with payload collection. CyberMesh does no submission, crawling or payload analysis. It distributes and verifies assessments, and in its design URLhaus-like feeds are **inputs** (pinned evidence snapshots and the independent corroboration that `block` requires), not competitors.

**What we borrow.** Per-entry status (online/offline), dated first-seen and last-seen fields, explicit takedown/false-positive reporting, and conservative fair-use polling (dumps are regenerated every 5 minutes and should not be fetched more often).

### 6.3 libp2p and rust-libp2p gossipsub

**What it is.** Gossipsub is libp2p's mesh-based publish/subscribe protocol:
- **v1.1** added peer scoring, peer exchange, flood publishing, explicit peers and defences against Sybil and eclipse attacks.
- **v1.2** added `IDONTWANT`.
- **v1.3** adds a partial-messages extension.

In rust-libp2p, `libp2p-gossipsub` **0.50.1** (2026-10-19, MIT; umbrella crate `libp2p` 0.57.1) supports v1.2 since 0.48 and the 1.3 partial-messages extension since 0.50. docs.rs failed to build 0.50.1; use the 0.49.2 docs or the source.

The behaviour offers:
- `MessageAuthenticity::Signed` (messages signed by the publishing peer's libp2p key)
- `ValidationMode::Strict`, the default: author, sequence number and signature are required
- application-level validation (`ConfigBuilder::validate_messages()` plus `Behaviour::report_message_validation_result` with `Accept` / `Reject` / `Ignore`), which feeds the peer score

**How CyberMesh uses it and what to keep in mind.**
- Gossipsub signatures authenticate the **peer ID that published a message**, not the operator organisation, and they do not survive storage or re-publication. CyberMesh's DSSE signatures are still required end to end.
- Gossipsub has no permissioning. Enforce the allow-list at the connection layer (`libp2p-allow-block-list` or connection gating) **and** in the application validator: reject any envelope whose signer is not in the current trust manifest.
- Keep gossipsub's peer score (a transport-level spam control) separate from CyberMesh's worker reputation.
- Use content-addressed message IDs (a hash of the envelope) to deduplicate.
- Set `max_transmit_size` to the largest legitimate envelope.

### 6.4 OpenTelemetry

**What it is.** A CNCF vendor-neutral observability framework (traces, metrics, logs; OTLP protocol). It is not a threat-sharing system. In `opentelemetry-rust` (crate `opentelemetry` 0.33.1), the Logs and Metrics API, SDK and OTLP exporter are **Stable**, while Traces are **Beta**.

**How CyberMesh uses it.** Optional operational telemetry for workers and the verifier: task latency, validation rejections, conflicts and resource-limit hits.

**What to keep in mind.** By default, do not put domain names, task payloads or operator-identifying data into span attributes or logs that leave the organisation. Telemetry from a security tool can reveal what an organisation is investigating. Prefer metrics over traces given the maturity status.

### 6.5 OpenTimestamps

**What it is.** A timestamping proof standard. Calendar servers aggregate submitted digests into Merkle trees and commit the roots to Bitcoin. A `.ots` proof is "pending" until the Bitcoin transaction confirms, which the client documentation describes as taking "a few hours". The `opentimestamps-client` README says that full verification needs a local Bitcoin Core node (a pruned node is fine); otherwise the verifier relies on a calendar to supply the path to the block header. The public calendars are free and donation-funded.

**How CyberMesh uses it.** As the planned optional anchor adapter. It proves that a release digest or log checkpoint **existed before** a Bitcoin block time. It does **not** prove the release is correct, and it does not prevent equivocation: a publisher can timestamp two different logs. Witness cosigning (6.9) addresses equivocation; OpenTimestamps does not.

**Practical notes.** Keep it optional and out of the extension's critical path. The Rust crate `opentimestamps` (0.2.0, MIT OR Apache-2.0) was last released in 2023-04, so an adapter speaking the calendar HTTP API or invoking the `ots` CLI may be easier to maintain.

### 6.6 Ethereum Attestation Service (EAS)

**What it is.** An open protocol (MIT) for attestations on EVM chains. A `SchemaRegistry` contract registers schemas; an `EAS` contract records attestations against a schema UID. It supports revocation, references between attestations and optional resolver contracts (which can attach payments). Off-chain attestations signed with EIP-712 are also supported. Each on-chain attestation costs gas.

**How CyberMesh differs.** CyberMesh deliberately uses no tokens and no smart contracts, and needs no chain to verify. On EAS anyone can attest, so trust must be layered on top; CyberMesh's trust comes from a governance-signed manifest.

**What we borrow.** Two concepts only:
- identify each payload schema by a content hash (or versioned `payloadType`)
- model corrections and appeals as explicit, signed records that reference and supersede an earlier entry, rather than silent edits

### 6.7 Google Safe Browsing (local-list model)

**What it is.**
- **v4 Update API:** clients keep a local database of SHA-256 **hash prefixes** per threat list, updated incrementally. A local prefix match triggers a full-hash request, so the provider learns only the prefix.
- **v5:** adds `hashLists` downloads and `hashes.search` (4-byte prefixes), and changes from v4's "allow-by-default" to "check-by-default". Clients download a "Global Cache" of likely-benign sites and check anything else in real time. An Oblivious HTTP gateway hides client IPs from Google.
- The Safe Browsing API "is for non-commercial use only"; commercial use goes to the Web Risk API.

**How CyberMesh differs.** Safe Browsing has far greater coverage and freshness, backed by Google's crawling and content analysis, and Chrome already uses it. Its lists are opaque and provider-signed, with no public provenance, appeals record or multi-party signing. CyberMesh's extension verifies the whole release offline: nothing is sent per lookup, which is simpler than prefix queries but only scales to modest list sizes.

**What we borrow.**
- If releases grow, a hash-prefix delta format for distribution.
- Versioned list states with incremental updates and checksums.
- The principle that lookups do not leak browsing to the publisher.

### 6.8 Sigstore, DSSE and in-toto

**What they are.**
- **DSSE** (v1.0.2) is a minimal signing envelope. It signs `PAE(payloadType, payload)` with `PAE = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, supports multiple signatures, and treats `keyid` as an unauthenticated hint.
- **in-toto attestations** put a typed `Statement` (subjects with digests, `predicateType`, predicate) inside DSSE.
- **Sigstore** provides keyless signing (OIDC identity → Fulcio short-lived certificate → Rekor transparency-log entry) and a "bundle" format. It underpins GitHub artifact attestations and PyPI attestations (PEP 740).

**How CyberMesh uses them.**
- DSSE is the envelope for tasks, results, manifests and releases.
- For worker results, consider an in-toto `Statement` whose subject is the pinned evidence-snapshot digest and whose predicate is the assessment. This makes results readable by existing in-toto tooling at little cost; it is optional.
- Use Sigstore **only for software artefacts** (worker binaries, extension packages). Threat-list releases use long-lived, governance-listed org keys with k-of-n signing, because Sigstore's identity model (OIDC accounts, a public Rekor log) is a different trust model and would add an online dependency to verification.

### 6.9 Certificate Transparency (RFC 6962 / RFC 9162) and C2SP

**What it is.**
- RFC 6962 defines append-only Merkle logs with leaf hash `SHA-256(0x00 ‖ leaf)`, interior node `SHA-256(0x01 ‖ left ‖ right)`, signed tree heads, and inclusion and consistency proofs.
- RFC 9162 ("CT 2.0") obsoletes it but is **Experimental**; deployed CT still largely uses 6962 structures.
- The current ecosystem is moving to tiled, static logs (C2SP `static-ct-api`, `tlog-tiles`) with checkpoints in the C2SP `signed-note` / `tlog-checkpoint` format and independent **witness cosignatures** (`tlog-cosignature`, `tlog-witness`) to detect split views.

**How CyberMesh uses it.** The release log follows RFC 6962 hashing, as already decided. The open problem for an offline browser verifier is split views: the publisher showing different logs to different clients. CT's answer is gossip and witnesses. Adopting C2SP checkpoints lets CyberMesh releases carry witness cosignatures from participating organisations, as Encompute's `CheckpointWitness` does, and the extension can then require at least one independent cosignature.

---

## 7. How CyberMesh differs from existing threat-sharing systems

**Where CyberMesh adds something:**

- **Verifiable provenance in the browser.** A release is checked offline against pinned keys: who signed, which operators agreed, and which feed corroborated a `block`. Safe Browsing, URLhaus and typical MISP feeds do not provide multi-party, end-to-end signatures that a browser extension can verify.
- **No single signing key.** k-of-n organisational signing means one stolen key cannot publish a release.
- **A public, append-only record.** A Merkle log of releases, corrections and appeals lets anyone check that a correction was published and that history was not rewritten.
- **Explicit separation of advice and blocking.** Worker agreement can only produce `warn`; `block` requires an independent reference feed. Reputation is never used as evidence that a domain is malicious.
- **Bounded, opt-in participation.** Organisations contribute resource-limited workers without sharing internal telemetry.

**Where CyberMesh is not better:**

- **A single well-run feed is simpler and often better.** OpenPhish, Safe Browsing or a commercial feed operated by analysts with crawlers and page-content analysis will usually have better recall, fewer false positives on lookalike domains, and much lower operating complexity than a federated network with a trust manifest, k-of-n ceremonies and appeals.
- **Distributed compute adds little to cheap lexical analysis.** The engine is deterministic and fast, so the verifier could compute every result itself in milliseconds. Multiple workers do not add detection power; they replicate it. Three operators running the same code over the same pinned evidence produce **correlated** outputs, so agreement shows correct execution, not correct judgement. The value of the worker layer is organisational (independent parties vouching that the published computation was run as specified, and detecting faulty or compromised workers), not analytical. That is why `block` correctly needs independent corroboration.
- **Lexical-only detection has a ceiling.** Without fetching pages, the engine cannot see credential forms, brand assets or redirects. Many phishing campaigns use compromised legitimate domains or free hosting subdomains, which lexical features do not flag.
- **Freshness.** Phishing domains often live for hours. A release pipeline with quorum verification and k-of-n signing adds latency that centrally operated feeds (minutes) do not have. Short expiry helps safety but does not make releases faster.
- **Corroboration depends on third-party feeds** whose terms restrict redistribution and commercial use (section 8). The most authoritative inputs may be the least publishable.
- **Network effects are not there yet.** MISP communities, abuse.ch and Spamhaus already have large contributor bases. CyberMesh should interoperate (MISP and STIX export) rather than compete.
- **Governance cost.** Onboarding organisations, rotating keys, holding signing ceremonies and handling appeals are ongoing human costs that a single provider absorbs internally.

---

## 8. Dataset licensing and access (November 2026)

### 8.1 Summary table

The "Probe" column shows `HEAD` responses on 2026-11-16 with no credentials.

| Source | Content | Licence or terms (as published) | Redistribution in a public Apache-2.0 repository | Current download URL | Auth | Probe |
|---|---|---|---|---|---|---|
| **URLhaus** (abuse.ch / Spamhaus) | Malware-distribution URLs | No data licence stated. The abuse.ch Terms of Use (effective 2025-11-04, last updated 2026-10-21) name CC0 **only** for Feodo Tracker, SSL Blacklist and YARAify. URLhaus is free under "fair use principles" for not-for-profit use by authenticated users; commercial use "may require a paid subscription, which will be managed by Spamhaus". §7.3 bars copying without consent and bars using data to train AI models without Spamhaus's written consent. | **No.** No grant; treat as not redistributable. | `https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv`; other export names are shown only after login | Free Auth-Key from `https://auth.abuse.ch/`, in the URL path | Old `/downloads/csv_recent/`, `/downloads/text_recent/`, `/downloads/hostfile/`: **410 Gone**. v2 path with an invalid key: **401** |
| **ThreatFox** (abuse.ch / Spamhaus) | Malware IOCs (domains, IPs, URLs, hashes) | Same abuse.ch terms as URLhaus. IOCs older than 6 months are not exposed in exports. | **No** | `https://threatfox-api.abuse.ch/v2/files/exports/<AUTH-KEY>/full.csv.zip`; other names after login | Auth-Key in the URL path (the same key works across abuse.ch platforms, per community reports) | Old `/export/csv/recent/`, `/export/json/recent/`: **410**. v2 with an invalid key: **401** |
| **Majestic Million** | Top 1M domains by referring subnets | "Licensed under a Creative Commons Attribution 3.0 Unported License" | **Yes, with attribution**, as a separately licensed data file (CC BY 3.0, not Apache-2.0) | `https://downloads.majestic.com/majestic_million.csv` (about 80 MB) | None | **200** |
| **Tranco** | Research top-sites ranking, aggregated | No licence stated for the list. The current default list combines Cisco Umbrella ("free of charge"), Majestic (CC BY 3.0), Farsight, Chrome UX Report (**CC BY-SA 4.0**) and Cloudflare Radar (**CC BY-NC 4.0**). The latest list API reports providers `crux, farsight, majestic, radar, umbrella`. Citation of the NDSS 2019 paper is expected. | **No** (mixed upstream terms, including non-commercial and share-alike) | `https://tranco-list.eu/top-1m.csv.zip` (307 → `/download/daily/top-1m.csv.zip`); permanent lists `https://tranco-list.eu/download/<LIST_ID>/1000000` | None for downloads; account key for the API | **307 → 200**. Latest list ID on 2026-11-16: `JZWZY` |
| **Cisco Umbrella top 1M** | Most-queried DNS names (includes TLDs and subdomains) | No licence or terms on the download page; Tranco describes it as "free of charge" | **No** (no grant) | `https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip`; historical `top-1m-<YYYY-MM-DD>.csv.zip` | None | **200** (about 12.8 MB) |
| **OpenPhish Community** | Phishing URLs, updated every 12 h | Terms of Use: "solely for your personal use"; "academic, independent, or personal research"; "not to use any part of the Services for any commercial purposes", explicitly including "product development, automation, customer protection" without written consent; no distribution without written permission | **No** | `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt` (`https://openphish.com/feed.txt` redirects there) | None (by use you accept the terms) | `feed.txt` **302 →** GitHub raw **200** |
| **PhishTank** (Cisco Talos) | Verified phishing URLs | FAQ: free to everyone, and commercial and non-commercial use of the API is "OK". Terms of Use link to a Cisco EULA. No open-data licence or redistribution grant found. | **No** (no explicit grant) | `https://data.phishtank.com/data/online-valid.{csv,json,xml}[.gz,.bz2]`; with key `https://data.phishtank.com/data/<APP_KEY>/online-valid.json.bz2` | App key recommended ("Without this key, you will be limited to a few downloads per day"). Whether new registration is open is unconfirmed; it was reported closed in 2020. | `.csv.bz2`: **429** (rate limited) |
| **Phishing.Database** (now `Phishing-Database/Phishing.Database`; `mitchellkrogza/...` redirects) | Phishing domains, links and IPs, status-tested with PyFunceble | Repository is **MIT**. Upstream sources are not documented ("pulls from several phishing intelligence feeds"), so data provenance is unclear. | **Legally permitted by MIT**, but **not recommended** (unknown upstream terms; live malicious domains) | `https://phish.co.za/latest/phishing-domains-ACTIVE.txt` (official). GitHub raw `https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt` (last updated **2026-10-02**) | None | phish.co.za: **503**. GitHub raw: **200** (about 11 MB) |
| *Feodo Tracker, SSL Blacklist* (abuse.ch; reference only) | Botnet C2 IPs; malicious TLS certificate SHA-1s | **CC0** per abuse.ch terms §3.4 | **Yes** | `https://feodotracker.abuse.ch/downloads/ipblocklist.csv`; `https://sslbl.abuse.ch/blacklist/sslblacklist.csv` | None | **200** |

### 8.2 Notes

- **URLhaus and ThreatFox.**
  - The 410 responses are the retirement of keyless downloads, not an outage. Community reports from OPNsense and OpenCTI place the cut-off around 2026-10-21/22. abuse.ch has not published an official date that this review could find.
  - The fix is to register at `auth.abuse.ch` and use the v2 export path with the key in the URL.
  - Treat the key as a secret: keep it out of logs, CI output and committed configs.
  - Do not rely on older statements, including in third-party tooling, that URLhaus data is CC0; the current terms do not say so.
  - Use by organisations operating CyberMesh workers may count as commercial use under §4.1.
- **OpenPhish Community.** The terms prohibit "customer protection" and "automation" without consent. Using it as an operational reference feed in CyberMesh would need written permission, even if the feed is free.
- **Tranco.** For reproducible evaluation, record the permanent list ID (for example `JZWZY`) rather than committing the list.
- **Cisco Umbrella.** Because the list is DNS-query based, it contains TLDs, infrastructure subdomains and some malicious domains. Do not treat it as a clean benign set.
- **Majestic.** Commit only a small top-N subset (for example the top 10,000). Ship it with `LICENSES/CC-BY-3.0.txt` and a REUSE/SPDX `.license` sidecar naming Majestic and the download date. The data file stays CC BY 3.0 inside an Apache-2.0 repository.
- **Phishing.Database.** The GitHub copy has not updated since 2026-10-02 and the official host returned 503 during the probe, so availability is currently uncertain.

### 8.3 Recommended sources

**(i) Committed demo data (in the public repository):**

| Purpose | Recommendation |
|---|---|
| Suspicious/malicious examples | **Synthetic domains created by the project under reserved names**: RFC 2606 / RFC 6761 `.test`, `.example`, `.invalid`, and `example.com/.net/.org` second-level labels, for example `paypa1-secure-login.example`. Licence-free. Ships no live malicious infrastructure. Avoids labelling real third-party domains as malicious in a public repository. Exercise TLD-based features through a test-only TLD risk table rather than real registrable names. |
| Benign examples | **Majestic Million top-N subset** (CC BY 3.0, with attribution and a licence sidecar), or a short hand-picked list of well-known domains. |
| Reference-feed format fixtures | Synthetic feed snapshots in the URLhaus/OpenPhish **format** (headers and columns only, synthetic rows). Optionally a small **Feodo Tracker** or **SSL Blacklist** snapshot (CC0) to test real-world parsing of a CC0 abuse.ch file. |
| Signed fixtures | Test keys and envelopes generated by the project, clearly marked test-only. |

**(ii) Evaluation-only data (fetched at evaluation time, pinned by SHA-256, never committed):**

| Source | Allowed use in evaluation | Constraint |
|---|---|---|
| Phishing.Database | Positive (phishing) set | MIT; provenance unclear; host availability uncertain |
| PhishTank | Positive set | Rate limits; app key may be unobtainable |
| OpenPhish Community | Positive set, **academic/personal research only** | No commercial, product or "customer protection" use without consent |
| URLhaus / ThreatFox | Malware-domain positives and reference-feed experiments | Auth-Key; not-for-profit fair use; no AI training |
| Tranco (by list ID), Cisco Umbrella | Benign/negative set and false-positive measurement | Do not commit; Umbrella contains some malicious names |
| Majestic Million (full) | Benign/negative set | CC BY 3.0 |

**Operational reference feed for `block`** (not demo, not evaluation): **no reviewed source is clearly usable without a licence decision.** See [section 9](#9-open-questions).

---

## 9. Open questions

1. **Reference-feed licensing for `block`.** Publishing a domain as `block` "corroborated by feed X" probably redistributes feed X's data. Options:
   - obtain written permission or a commercial licence (Spamhaus for URLhaus/ThreatFox, OpenPhish premium/academic)
   - use Google Web Risk under its commercial terms (whether its results may be redistributed would need checking)
   - restrict `block` corroboration to CC0 or explicitly permissive sources (none found for phishing domains)
   - publish only a corroboration digest and let each client check its own licensed feed locally
   - this needs a decision before the first non-demo release
2. **Rights-holder decision.** Will the owner of Encompute and regaudit-fhe grant any specific files under Apache-2.0? This review assumes not; reimplementation is cheap.
3. **Checkpoint format.** Bespoke CyberMesh checkpoints or C2SP `tlog-checkpoint` / `signed-note` (interoperable with existing witnesses)? This is an implementation choice within the agreed RFC 6962 design.
4. **Ed25519 edge-case policy.** Confirm that the extension (Chrome ≥ 137 Web Crypto) and `ed25519-dalek` `verify_strict` agree on the frozen edge-case vectors, and decide the minimum Chrome version.
5. **PhishTank registration.** Confirm whether new application keys are obtainable.

---

## 10. References

**Owner repositories**

- Encompute: https://github.com/BAder82t/Encompute; release v0.3.3: https://github.com/BAder82t/Encompute/releases/tag/v0.3.3; advisory: https://github.com/BAder82t/Encompute/security/advisories/GHSA-rm8x-939m-3fgp
- regaudit-fhe: https://github.com/BAder82t/regaudit-fhe
- fhe-oracle-oss: https://github.com/BAder82t/fhe-oracle-oss
- fhe-attack-replay: https://github.com/BAder82t/fhe-attack-replay
- verify-action: https://github.com/BAder82t/verify-action

**Prior art and specifications**

- MISP: https://github.com/MISP/MISP; sharing and synchronisation: https://circl.lu/doc/misp/sharing/; warninglists: https://github.com/MISP/misp-warninglists
- URLhaus API and exports: https://urlhaus.abuse.ch/api/; about: https://urlhaus.abuse.ch/about/
- rust-libp2p gossipsub changelog: https://github.com/libp2p/rust-libp2p/blob/master/protocols/gossipsub/CHANGELOG.md; crate: https://crates.io/crates/libp2p-gossipsub; gossipsub v1.1 spec: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md; v1.2 spec: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.2.md
- OpenTelemetry Rust (status table): https://github.com/open-telemetry/opentelemetry-rust; OpenTelemetry docs: https://opentelemetry.io/docs/
- OpenTimestamps: https://opentimestamps.org/; client: https://github.com/opentimestamps/opentimestamps-client; Rust crate: https://crates.io/crates/opentimestamps
- Ethereum Attestation Service contracts: https://github.com/ethereum-attestation-service/eas-contracts; docs: https://docs.attest.org/
- Google Safe Browsing API reference (v5): https://developers.google.com/safe-browsing/reference; Web Risk: https://cloud.google.com/web-risk
- DSSE protocol: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md; envelope: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md; in-toto attestation framework: https://github.com/in-toto/attestation; Sigstore: https://docs.sigstore.dev/
- RFC 6962: https://www.rfc-editor.org/rfc/rfc6962; RFC 9162: https://www.rfc-editor.org/rfc/rfc9162; RFC 8785 (JCS): https://www.rfc-editor.org/rfc/rfc8785; RFC 2606: https://www.rfc-editor.org/rfc/rfc2606; RFC 6761: https://www.rfc-editor.org/rfc/rfc6761
- C2SP: tlog-checkpoint https://c2sp.org/tlog-checkpoint; signed-note https://c2sp.org/signed-note; tlog-cosignature https://c2sp.org/tlog-cosignature; tlog-witness https://c2sp.org/tlog-witness; static-ct-api https://c2sp.org/static-ct-api
- Chrome Web Crypto Ed25519, intent to ship: https://groups.google.com/a/chromium.org/g/blink-dev/c/T2kriFdjXsg; status entry: https://chromestatus.com/feature/4913922408710144; Igalia note on Chrome 137: https://blogs.igalia.com/jfernandez/?p=1950
- Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs" (IACR ePrint 2020/1244): https://eprint.iacr.org/2020/1244
- Crates: `ed25519-dalek` https://crates.io/crates/ed25519-dalek; `serde_jcs` https://crates.io/crates/serde_jcs; `ct-merkle` https://crates.io/crates/ct-merkle

**Datasets and terms**

- abuse.ch Terms of Use: https://abuse.ch/terms-of-use/; authentication portal: https://auth.abuse.ch/
- ThreatFox API: https://threatfox.abuse.ch/api/; exports: https://threatfox.abuse.ch/export/
- Community reports of the keyless-download retirement: https://github.com/opnsense/core/issues/11078; https://github.com/OpenCTI-Platform/connectors/issues/8153; https://github.com/OpenCTI-Platform/connectors/issues/8280
- Majestic Million: https://majestic.com/reports/majestic-million
- Tranco: https://tranco-list.eu/; latest list API: https://tranco-list.eu/api/lists/date/latest; paper (Le Pochat et al., NDSS 2019): https://www.ndss-symposium.org/ndss-paper/tranco-a-research-oriented-top-sites-ranking-hardened-against-manipulation/
- Cisco Umbrella popularity list: https://s3-us-west-1.amazonaws.com/umbrella-static/index.html
- OpenPhish feeds: https://openphish.com/phishing_feeds.html; terms: https://openphish.com/terms.html; community feed repository: https://github.com/openphish/public_feed
- PhishTank developer information: https://phishtank.org/developer_info.php; FAQ: https://phishtank.org/faq.php; background: https://en.wikipedia.org/wiki/PhishTank
- Phishing.Database: https://github.com/Phishing-Database/Phishing.Database; source repository: https://github.com/Phishing-Database/phishing
- Feodo Tracker: https://feodotracker.abuse.ch/; SSL Blacklist: https://sslbl.abuse.ch/

# Contributing

Thank you for helping. CyberMesh is security software, so changes are held to a careful,
evidence-based standard.

## Ground rules

- **No inbound code execution, scanning or crawling** features for workers. Task kinds are
  allow-listed and data-only.
- **No tokens, coins or speculative incentives.**
- **No marketing claims.** Documentation must state what was measured or tested and how.
- Any change that can alter engine output for the same input must bump `ENGINE_VERSION`
  and update the golden vectors.
- Any change to signed formats needs a protocol version decision and updated test vectors.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
(cd apps/browser-extension && npm ci && npm test)
```

Fuzzing (nightly): `cd fuzz && cargo +nightly fuzz run <envelope|task|release|ots|domain>`.

## Pull requests

1. Open an issue first for anything larger than a small fix.
2. Write tests first for behaviour changes. Security fixes need a regression test.
3. Keep commits focused, using conventional commit messages (`feat:`, `fix:`, `docs:` and so on).
4. Explain the security trade-offs of design changes in the PR description.
5. CI must pass: formatting, clippy, tests, dependency audit, extension tests, secret scan
   and SBOM.

By contributing you agree that your contributions are licensed under the Apache License 2.0.

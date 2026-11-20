# Build integrity: verifying CyberMesh binaries

CyberMesh release binaries are built in CI, from the tagged commit, by `.github/workflows/release.yml`.

- Each target is built twice on separate machines, and the release stops unless both copies are byte-identical.
- The binaries carry a signed SLSA build provenance attestation.
- Linux binaries can be rebuilt bit for bit by anyone with Docker.

This covers the *software*. The threat-intelligence releases that CyberMesh nodes co-sign are separate and are verified with `cybermesh release verify` ([architecture.md](architecture.md)).

## What a release contains

| File | What it is |
|---|---|
| `cybermesh-<version>-x86_64-unknown-linux-gnu` | Linux x86-64, built in `rust:1.98.1-slim-bookworm` pinned by digest (`deploy/docker/Dockerfile`). Needs glibc 2.34 or later (the newest symbol version it uses): Debian 12, Ubuntu 22.04, RHEL 9 or newer. |
| `cybermesh-<version>-aarch64-unknown-linux-gnu` | Linux arm64, built in the same image. |
| `cybermesh-<version>-aarch64-apple-darwin` | macOS on Apple silicon, built on a GitHub macOS 15 runner. Not notarised: Gatekeeper warns on first run. |
| `cybermesh-sbom.spdx.json` | Software bill of materials (SPDX), generated from the tagged source. |
| `SHA256SUMS` | SHA-256 of every file above. |
| `cybermesh-provenance.sigstore.json` | The provenance attestation (a Sigstore bundle), for offline verification. |

## How a release is built

1. A maintainer bumps the version in a pull request, merges it, and pushes a `v<version>` tag on the merge commit.
2. `release.yml` builds every target twice on separate runners. The `verify` job compares the two copies of each binary and fails if any pair differs. It then writes `SHA256SUMS`.
3. The `publish` job checks that the tag matches the workspace version and generates the SBOM.
4. It then creates a provenance attestation for everything in `SHA256SUMS`, with GitHub artifact attestations. This is signed through Sigstore's public instance and recorded in its transparency log.
5. It attaches all files to a draft GitHub release. The maintainer adds the notes and publishes the release.

Pull requests that change the build (the workflow, the build script, the toolchain, `Cargo.lock` or the Dockerfile) run step 2 only: every target is built twice and compared, and nothing is published.

## Verifying a binary

**1. The checksum.** Download the binary and `SHA256SUMS` from the release, then run:

```bash
sha256sum --ignore-missing -c SHA256SUMS        # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
```

**2. The provenance** (needs the GitHub CLI):

```bash
gh attestation verify cybermesh-<version>-x86_64-unknown-linux-gnu \
  --repo BAder82t/CyberMesh \
  --signer-workflow BAder82t/CyberMesh/.github/workflows/release.yml
```

This checks that the file was built by this repository's release workflow on a GitHub-hosted runner. The output shows the commit and tag it was built from. To verify without fetching the attestation from GitHub, add `--bundle cybermesh-provenance.sigstore.json`.

What this does *not* show: that the source is free of bugs or backdoors, or that GitHub's build platform was not compromised. The third check does not depend on GitHub.

**3. Rebuild it yourself.** For a Linux binary, with Docker:

```bash
git clone https://github.com/BAder82t/CyberMesh && cd CyberMesh
git checkout v<version>
scripts/build-release.sh --docker x86_64-unknown-linux-gnu dist   # or aarch64-unknown-linux-gnu
sha256sum dist/cybermesh-*                                        # compare with SHA256SUMS
```

The build runs inside the same pinned image as the release, so the hash should match exactly on any machine.

A macOS binary is rebuilt with `scripts/build-release.sh aarch64-apple-darwin dist` and the 1.98.1 toolchain. Rebuilds from a different checkout path, toolchain location and Cargo home were checked to be byte-identical. A different Xcode or SDK version, however, does give a different binary. A rebuild of the same sources with Xcode 27.2 did not match the binary built on GitHub's `macos-15-arm64` image, which ships an older Xcode. So check a macOS binary on a Mac with the same Xcode version as that image, or rely on its provenance.

## What makes the build reproducible

`scripts/build-release.sh` controls everything that could differ between machines:
- The toolchain is pinned (`rust-toolchain.toml`, and the image digest for Linux), and dependencies come from `Cargo.lock` (`--locked`).
- Incremental compilation is off. The release profile uses one codegen unit and strips symbols.
- **Paths of the build machine** are replaced with fixed names, so no directory or user name is embedded in the binary:
  - `--remap-path-prefix` does this for the checkout, the Cargo home and the standard library's sources;
  - `-ffile-prefix-map` (`CFLAGS`, `ASMFLAGS`) does the same for C and assembly that build scripts compile, for example in `ring`.
- **On macOS, the linker derives the binary's `LC_UUID` from object paths** before symbols are stripped. So the build uses a fixed target directory, and `-oso_prefix` drops the toolchain's location.

Without these, two macOS builds of the same commit differed in 48 bytes: the UUID, plus the code-signature hash that covers it.

## Assurance level

**SLSA level.** This is SLSA v1.0 **Build Level 2**: the build runs on a hosted platform and its provenance is signed by that platform. It is not Build Level 3, which would need the build to run in an isolated, reusable workflow that the calling workflow cannot influence.

**Reproducibility** goes further than the SLSA level in one respect: independent rebuilds can check the Linux binaries without trusting GitHub.

## Not covered yet

- Windows binaries.
- Apple code signing and notarisation.
- Published container images.
- A packaged browser extension.
- SLSA Build Level 3 (an isolated reusable workflow).
- Verification of the provenance by the binary itself (for example on self-update).

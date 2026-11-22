# Security policy

CyberMesh is a research MVP (v0.3.6). It has had internal reviews but **no external security
audit**, and it is not production-ready.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Use GitHub's private vulnerability reporting:
  <https://github.com/BAder82t/CyberMesh/security/advisories/new>
- Include affected versions or commits, a description, reproduction steps or a proof of
  concept, and the impact you expect.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | within 5 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan for confirmed HIGH/CRITICAL issues | within 30 days where possible |
| Public advisory | after a fix is available, coordinated with the reporter |

We credit reporters in the advisory unless they prefer otherwise. Good-faith research that
respects this policy, avoids privacy violations and service disruption, and does not touch
other participants' systems will not be pursued legally.

## Scope

In scope: everything in this repository (crates, CLI, browser extension, deployment files,
protocol and release formats).

Out of scope: third-party feeds and calendars, findings that need a threshold of governance
or release-signing keys, and denial of service by an enrolled peer within its rate allowance
(documented residual risk).

## Supported versions

Only the latest commit on `main` and the latest tagged release receive fixes.

Release binaries come with SHA-256 checksums, an SBOM and a signed build provenance attestation, and the Linux binaries can be rebuilt bit for bit. [docs/build-integrity.md](docs/build-integrity.md) explains how to verify them.

## False positives

A wrongly listed domain is not a security vulnerability. Use the
[false-positive form](https://github.com/BAder82t/CyberMesh/issues/new?template=false-positive.yml).

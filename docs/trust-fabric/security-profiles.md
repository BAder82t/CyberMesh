# Trust Fabric: security profiles

Status: experimental, unaudited. Nothing here is on by default. The existing CyberMesh
profile is unchanged.

| Profile | Secure if | Fails if |
|---|---|---|
| Standard computational (today: Ed25519, DSSE, Noise, SHA-256) | the underlying computational assumptions hold | P = NP-style breaks, large quantum computers (Ed25519) |
| Post-quantum computational (planned) | lattice/hash assumptions hold | those assumptions fail |
| Information-theoretic (planned, opt-in) | the model below holds | the model is violated; no computation can rescue it |

## What the information-theoretic profile may rely on

Only: pre-provisioned secret material (counted and consumed), private channels between
parties for share delivery, an honest-participant threshold, and statistical error bounds
that are stated. It must not rely on Ed25519, DSSE, governance signatures, Merkle
commitments, transparency logs, AES, ChaCha20, HKDF or any pseudorandom expansion of a short
seed. If a session cannot meet this it fails closed; it never downgrades to a computational
profile.

## What stays computational in CyberMesh regardless

Node identity, signed task/result envelopes, the trust manifest, CT proofs, anchoring and the
libp2p transport are all computationally secured. They may carry Trust Fabric messages but
their protection is never counted toward an information-theoretic claim.

## Why this is not "unbreakable"

Information-theoretic security needs secret keys at least as long as the data protected (for
one-time-pad confidentiality) plus authentication keys, supplied ahead of time. Capacity is
limited by that supply. Shamir sharing hides a secret only from fewer than `k` colluding
holders; it gives no authentication and, alone, no error detection of which share is wrong.

## Components and status

| Crate | Status |
|---|---|
| cybermesh-sharing (Shamir over GF(2^8), Reed-Solomon correction, proactive refresh) | implemented, unit and property tests, unaudited |
| cybermesh-entropy (one-time pools, crash-safe cursor, erasure) | implemented, unit tests incl. crash, torn-write and concurrency, unaudited |
| cybermesh-trust, -transport, -routing, -private-compute | not started |

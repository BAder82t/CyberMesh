# Trust Fabric: authentication

Status: experimental, unaudited. Implemented in `crates/cybermesh-trust` (`mac` module).

## Construction

Wegman-Carter: `tag = H_r(message) XOR pad`.

* `H_r` splits the message into 16-byte blocks (the last zero-padded), appends a length block,
  and evaluates the result as a polynomial in the key `r` over GF(2^128) (polynomial
  `x^128 + x^7 + x^2 + x + 1`) by Horner's rule. This is not GHASH or Poly1305 and is not
  compatible with them.
* `r` is 16 secret uniform bytes, reused across messages.
* `pad` is 16 fresh secret uniform bytes per tag, taken from a `cybermesh-entropy` pool of
  purpose `Authentication`. A `Reservation` is consumed by use, so a pad cannot be used twice.
* The receiver recomputes the tag with its own copy of `r` and the matching pad, compares in
  constant time, and counts a mismatch as a failed attempt.

## Security statement

For two different messages of at most `n` blocks the hash difference is a non-zero polynomial
in `r` of degree at most `n + 1` (the length block makes different lengths differ; equal
lengths differ in some block). So `H` is `(n+1)/2^128`-almost-universal. With a fresh uniform
pad per tag, tags reveal nothing about `r`, and an adversary with **unbounded computation**
that makes `q` forgery attempts succeeds with probability at most `q (n+1) / 2^128`
(`forgery_bound`). With the defaults (16 MiB messages, 65,536 allowed failures) that is below
`2^-90`.

Evidence: the polynomial claim is checked **exhaustively over GF(2^8)** with the same
construction (any two different messages of up to 3 blocks collide for at most 4 of 256 keys).
Removing the length block makes that test and the padding-ambiguity test fail. The
Wegman-Carter step from almost-universality to unforgeability is the standard textbook one and
is cited, not re-proved here; the statement has had no independent review.

## What must hold

* Key and pads come from pools whose provenance is a shared secret (provisioned or QKD), never
  pseudorandom or public (`cybermesh-entropy` refuses those). Both parties need identical
  material and must use the same pad offset for the same message.
* Failures are bounded: `Verifier` stops verifying once its budget is spent (`KeyRetired`) and
  the key must be replaced. A pad is spent on a failed check too.
* A failed verification does not tell which of message, tag or pad was wrong.

## What it is not

* **Pairwise and symmetric.** The receiver holds the same key and could forge, so a tag
  convinces only the receiver: no public verifiability, no non-repudiation, no use as a
  signature. Governance and identity signatures in CyberMesh stay Ed25519.
* **Not replay or order protection by itself.** It authenticates exactly the bytes given.
  Binding session id, direction and sequence number into those bytes is the transport's job
  (not built yet).
* **Shares are authenticated separately**, see the next section.
* Key material is consumed: authentication costs 16 bytes of pad per message plus the key.
* The multiplication has no secret-dependent branches or tables, but there has been no timing
  review, and `unsafe` is forbidden but compiler output has not been inspected.

## Authenticated shares (`shares` module)

Information checking in the Rabin-Ben-Or style. A dealer tags each share of a sharing with a MAC
key the holder never sees; the verifier who will reconstruct holds a copy of the same material
from a pairwise `Authentication` pool. The holder keeps `(share, tag)` and presents both.

* One reservation per dealing, `16 * (1 + n)` bytes: a fresh hash key and one pad per holder
  slot (slot = share index - 1). The authenticated bytes are a domain string, the pool id, the
  block offset and the share's full encoding (set, epoch, threshold, index, length, data), so a
  tag cannot be moved to another share, index, set, epoch or dealing.
* The verifier checks every presented share and drops the ones that fail **before**
  reconstruction, then reconstructs from the authentic ones, cross-checking any beyond the
  threshold. The result is the dealer's secret or an error. With 3-of-5 shares and any two
  altered, all 10 combinations recover the real secret and name the bad shares; plain
  Reed-Solomon decoding returned a wrong secret for 6 of those 10 (`limitations.md`). With three
  altered the result is `TooFewAuthentic`, never a wrong secret.
* Every mismatch counts against a failure budget; a spent budget retires the dealing's material.

Limits: a valid tag only says the dealer issued this share unchanged. A **dishonest dealer** that
tags shares of different polynomials is caught only when more than `k` shares are presented (the
consistency check); with exactly `k` it goes unnoticed (a test shows both). Verifiable secret
sharing is not built. Only the verifier holding the material can check a tag (no public
verification), and each verifier needs its own pairwise material. **Proactively refreshed
shares carry no tag**: authenticated refresh is not built, and a refreshed sharing must be
re-dealt to be authenticated. The verifier's block lives in memory only; if it is lost the
dealing can no longer be checked and verification fails closed.

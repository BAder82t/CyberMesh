# Trust Fabric: known limitations

The cross-cutting critical issues (backup restoration, peer synchronisation, the unproved
handshake) are in [known-issues.md](known-issues.md).

## cybermesh-sharing

* Not verifiable. Plain `reconstruct` detects a wrong share only when more than `k` shares are
  given and cannot name it. `reconstruct_robust` (Berlekamp-Welch, per byte) corrects up to
  `e = (m - k) / 2` wrong shares among the `m` given and names them, which is the
  Reed-Solomon bound `2e + s <= n - k` with `s` missing shares simply not supplied.
* **Past that bound the robust decoder can return a wrong secret with no error.** In the
  tests, with n=5, k=3 (e=1), 6 of the 10 ways to corrupt two shares decoded to a wrong
  secret and 4 failed. Robust reconstruction is therefore only safe if the number of wrong
  shares is bounded by something else (authenticated shares, a trust assumption on holders).
  It is correction, not authentication; `cybermesh-trust::shares` adds the authentication (altered shares are rejected before decoding), but only for shares tagged by the dealer, not for refreshed ones. When `m - k` is odd, one unit of redundancy is unused;
  a mixed correct-and-detect mode is not built.
* Elimination is variable-time on secret data.
* Perfect secrecy needs fresh uniform secret coefficients. `OsRandom` is the OS CSPRNG: that
  is computational randomness, fine for local generation, but it is not shared secret
  randomness between parties and not information-theoretic entropy. Treat sharing generated
  with it as perfectly secret only relative to the assumption that the OS source is uniform.
* No authentication of shares or of the label (set id, epoch). An active attacker can alter
  them; authentication needs a separate information-theoretic MAC layer (not built).
* Field arithmetic avoids secret-dependent branches, but the crate has had no timing review
  and the final comparisons are not constant time.
* Zeroization on drop is best effort: the compiler, swap and core dumps are outside its reach.
* Proactive refresh (`zero_sharing`, `refresh_share`) re-randomises shares of the same secret and
  steps the epoch; shares of different epochs never combine. It assumes **honest dealers**:
  a dealer that shares a non-zero polynomial silently changes the secret and every check still
  passes (a test demonstrates it). Catching that needs verifiable secret sharing, not built.
* Refresh also assumes private authenticated channels for the deltas, that all holders add
  exactly the same set of dealers' deltas (a holder that misses one is out of step and
  reconstruction then fails or yields garbage), erasure of the old share and the deltas, and
  fresh randomness per dealing. None of these are enforced by the crate.
* The mobile-adversary guarantee is the standard one: an adversary holding fewer than `k` shares
  in every epoch, with erasure between epochs, learns nothing. It does not cover an adversary
  that reaches `k` shares inside one epoch, nor one that sees a dealer's randomness.
* No redistribution to a new threshold or membership (adding or removing holders) yet.
* Maximum 255 shares (GF(2^8)).

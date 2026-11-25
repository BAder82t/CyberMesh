# Trust Fabric: known limitations

## cybermesh-sharing

* Not verifiable. A wrong share is detected only when more than `k` shares are given, and the
  holder of the wrong share is not identified. Robust (Reed-Solomon) reconstruction with
  `2e + s <= n - k` is not implemented yet.
* Perfect secrecy needs fresh uniform secret coefficients. `OsRandom` is the OS CSPRNG: that
  is computational randomness, fine for local generation, but it is not shared secret
  randomness between parties and not information-theoretic entropy. Treat sharing generated
  with it as perfectly secret only relative to the assumption that the OS source is uniform.
* No authentication of shares or of the label (set id, epoch). An active attacker can alter
  them; authentication needs a separate information-theoretic MAC layer (not built).
* Field arithmetic avoids secret-dependent branches, but the crate has had no timing review
  and the final comparisons are not constant time.
* Zeroization on drop is best effort: the compiler, swap and core dumps are outside its reach.
* No proactive refresh, redistribution or dynamic membership yet.
* Maximum 255 shares (GF(2^8)).

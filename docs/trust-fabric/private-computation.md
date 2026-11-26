# Trust Fabric: private computation

Status: experimental, unaudited. Implemented in `crates/cybermesh-private-compute`. A
single-process **simulation** of the parties, not a networked implementation.

## What is built

A BGW-style baseline for arithmetic circuits over GF(2^8) (values are bytes; addition and
subtraction are XOR; arithmetic wraps in the field, not the integers). Party `j` holds the
evaluation at the point `j` of a random degree-`t` polynomial whose value at 0 is the secret.

| Operation | How | Communication |
|---|---|---|
| input | the owner shares its value with a fresh degree-`t` polynomial | `n - 1` elements |
| add, subtract, add or multiply by a public constant | local | none |
| multiply | each party multiplies its two shares (a point of a degree-`2t` polynomial), re-shares the product with a fresh degree-`t` polynomial, and every party recombines with the Lagrange coefficients at 0 (**degree reduction**) | `n(n-1)` elements, one round per multiplicative layer |
| output | all shares are opened; they must lie on a polynomial of degree at most `t` | `n(n-1)` elements |
| public polynomial at a secret point | Horner's rule | one multiplication per degree |
| secret polynomial at a public point | linear combination | none |

Parameters: `1 <= t`, `t + 1 <= n <= 255`; a circuit with a multiplication needs `n >= 2t + 1`.
Rounds: 1 for inputs, 1 per multiplicative layer (independent multiplications share a round),
1 for the opening. Preprocessing: none. The counts in `Stats` come from the messages the
simulation actually exchanged and equal these formulas (tested).

## Security model, exactly

| Requirement | Value |
|---|---|
| Adversary | **semi-honest**: follows the protocol, inspects everything it receives; computationally unbounded |
| Corruption | up to `t` parties, `n >= 2t + 1` when multiplying |
| Interaction | as above |
| Preprocessing | none |
| Randomness | fresh uniform secret bytes for every sharing (`cybermesh_sharing::RandomSource`; in the simulation one source stands for all parties' independent sources) |
| Not covered | **malicious parties**, abort or fairness, any `t` parties colluding beyond the threshold |

Privacy against `t` semi-honest parties is the classical BGW result for this construction: the
proceedings text states unconditional security for fewer than `n/2` passive and fewer than `n/3`
active corruptions and reduces the degree of the degree-`2t` product polynomial (`literature-review.md`,
`bgw1988` V2; `grr1998` V1 for degree reduction and randomisation in one step). The tests check it
on small instances; they are not a proof:

* For `n = 5, t = 2`, the pair of shares two parties receive of an input takes every one of the
  65,536 values exactly once as the dealer's randomness varies, for two different secrets.
* For one multiplication gate at `n = 3, t = 1`, for 4 input pairs and 300 target views each,
  every view the corrupt party could see is produced, by exactly one choice of randomness,
  whatever the inputs are.

## What it does not do (tested where possible)

* **A malicious party breaks it silently.** A party that adds an error to its product before
  re-sharing makes the output a valid degree-`t` sharing of a wrong value; the output check
  passes. A test shows the result equals the honest one plus that party's Lagrange weight times
  the injected error.
* **The output check catches only inconsistent opened shares,** and only when there is a spare
  share (`n > t + 1`); at `n = t + 1` a wrong opened share goes through (tested).
* Active security needs verifiable secret sharing and `n >= 3t + 1` (and, for the general
  adversary structures of `cybermesh-trust`, the `Q3` condition). Not built.
* 256-element field: not suitable as is for arithmetic on large integers; there is no encoding
  layer.
* Network, party authentication, message loss, party crashes and the transport are out of scope;
  messages are in-process values. Combining this with `cybermesh-transport` and the routing plans
  is not built.

## Research items, no claim

Packed secret sharing, homomorphic secret sharing, algebraic-geometry codes, Schur-product and
multiplication-friendly codes, tensor representations, and any asymptotic reduction of the
communication or secret-resource cost below gate-by-gate BGW (the directive's "Theorem F") are
**not implemented and nothing is claimed**. This crate is the baseline against which such a
claim would have to be measured, under the same security model.

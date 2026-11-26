//! Secret-shared computation, a BGW-style baseline (EXPERIMENTAL, unaudited).
//!
//! Parties hold Shamir shares (degree `t` polynomials over GF(2^8), party `j` at the point `j`) of
//! the values on the wires of an arithmetic [`Circuit`] and compute on the shares:
//!
//! * addition, subtraction (both XOR in this field), and constants: **local**, no communication;
//! * multiplication: each party multiplies its two shares (a point of a degree-`2t` polynomial),
//!   re-shares the product with a fresh degree-`t` polynomial and every party recombines with the
//!   Lagrange coefficients (**degree reduction**): one round, `n(n-1)` field elements;
//! * output: the shares are opened and checked to lie on a polynomial of degree at most `t`.
//!
//! [`run`] simulates all `n` parties in one process with explicit per-party views, so privacy can be
//! checked and communication counted. It is not a networked implementation.
//!
//! # Security model, exactly
//!
//! | Requirement | Value |
//! |---|---|
//! | Adversary | **semi-honest** (follows the protocol, looks at what it sees), computationally unbounded |
//! | Corruption | up to `t` parties, with `n >= 2t + 1` when the circuit multiplies |
//! | Interaction | 1 round for inputs, 1 per multiplicative layer, 1 for the output |
//! | Preprocessing | none |
//! | Communication | `n - 1` elements per input, `n(n-1)` per multiplication and per opening |
//! | Randomness | fresh uniform secret bytes for every sharing (`RandomSource`) |
//!
//! Privacy against `t` semi-honest parties is the classical BGW result for this construction
//! (thresholds `t < n/2` passive, `t < n/3` active, read in the proceedings text; see
//! `docs/trust-fabric/literature-review.md`);
//! the tests check it exhaustively for the sharing and for one multiplication gate on a small
//! instance, not as a proof. **Not secure against malicious parties**: a party that deviates while
//! re-sharing a product corrupts the result silently (a test shows it), and the output check can
//! detect only inconsistent opened shares. Active security needs verifiable secret sharing and
//! `n >= 3t + 1`, which are not built.
//!
//! The field has 256 elements: values are single bytes, and arithmetic wraps in GF(2^8), not in the
//! integers. Packed secret sharing, homomorphic secret sharing, algebraic-geometry codes and any
//! asymptotic compression of the communication are research items with **no claim** here.

#![forbid(unsafe_code)]

mod circuit;
mod protocol;

pub use circuit::{Circuit, CircuitBuilder, Gate, Wire};
pub use protocol::{ComputeError, Params, Run, Stats, run};

#[cfg(test)]
mod tests;

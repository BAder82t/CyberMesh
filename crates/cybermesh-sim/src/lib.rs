//! Deterministic simulator for the Trust Fabric routing and secret-budget model.
//!
//! It runs thousands of virtual participants spread over administrative domains, with concurrent
//! sessions competing for per-link one-time-pad budgets, random and correlated failures (link
//! failures, whole-domain outages), static and mobile adversaries that corrupt domains, a router
//! that learns of failures and corruption only after a delay, and provisioning that replenishes
//! the budgets. Each message is planned with `cybermesh-routing` against what the router knows and
//! judged against the truth.
//!
//! # What the numbers are
//!
//! **Simulated, not measured on real infrastructure.** The topology, failures, adversary and
//! traffic are generated from a seed by [`SimRng`], a deterministic generator that is **not**
//! secret randomness and deliberately does not implement the Trust Fabric's `RandomSource`
//! trait, so it cannot be used as key material by accident. The same [`Scenario`] gives the same
//! [`Report`] on every machine. Results depend on the generator's topology, which is a sparse
//! random graph with a ring inside each domain: they show how the model behaves, not how a
//! particular real network would.
//!
//! The simulator models routing, planning and secret budgets. It does **not** run the sharing,
//! MAC or transport code on bytes; it counts shares and budgets and applies the rules those crates
//! establish (`k` of `n` shares, authenticated or error-corrected tampering, per-hop pad
//! consumption).

#![forbid(unsafe_code)]

mod engine;
pub mod experiments;
mod report;
mod rng;
mod scenario;

pub use engine::{Drain, drain_bound, simulate};
pub use report::{Report, Table};
pub use rng::SimRng;
pub use scenario::{
    AdversaryCfg, ProtectionCfg, RECORD_OVERHEAD, RequirementCfg, Scenario, SimError,
};

#[cfg(test)]
mod tests;

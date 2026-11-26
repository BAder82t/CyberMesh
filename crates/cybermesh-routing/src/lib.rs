//! Trust-aware routing for the Trust Fabric (EXPERIMENTAL, unaudited).
//!
//! Given a graph of participants, administrative domains and links with per-direction secret
//! budgets, this crate finds the paths over which the shares of a message can travel so that an
//! adversary controlling some domains cannot read or silently change it:
//!
//! * [`disjoint_paths`]: minimum-cost vertex-, edge- or **domain**-disjoint paths, avoiding
//!   excluded domains, failed nodes and links, and links whose secret budget cannot carry the
//!   message (min-cost max-flow, vertex splitting).
//! * [`Requirement`] / [`plan_transmission`]: turn "tolerate `t` corrupt domains and `f` path
//!   failures" into a number of disjoint paths and sharing parameters `(n, k)`.
//! * [`Router`]: a plan that survives failures (re-plan on failure) and spends and replenishes
//!   the per-link secret budgets atomically.
//! * [`wire_secret_flow`]: a max-flow bound on how many wire bytes per-hop one-time-pad routing
//!   can move. It is **not** the information-theoretic capacity of the network (open research).
//!
//! # Model and assumptions
//!
//! * A path is secret and unaltered if no domain on it is corrupt. **Domain-disjoint** paths mean
//!   an adversary controlling `t` domains touches at most `t` paths, apart from the domains of the
//!   two endpoints, which are trusted by definition.
//! * To keep the problem polynomial each non-endpoint domain is contracted to one relay vertex
//!   (general colour-disjoint paths are hard). This is exact when the domain's nodes are
//!   mutually reachable inside it; paths are stitched with the shortest internal route, and a
//!   domain that cannot provide one fails closed ([`RoutingError::DomainDisconnected`]).
//! * "Logically distinct paths are independent" is **not assumed**: the only independence modelled
//!   is the domain structure the operator supplies. Shared infrastructure and common owners
//!   across domains are outside the model.
//! * Link secret budgets are local bookkeeping of `cybermesh-entropy` pools; this crate does not
//!   touch the pools.

#![forbid(unsafe_code)]

mod bound;
mod flow;
mod graph;
mod paths;
mod plan;

pub use bound::wire_secret_flow;
pub use graph::{Graph, Link, NodeId};
pub use paths::{Constraints, Disjointness, Path, RoutingError, disjoint_paths};
pub use plan::{
    Allocation, Plan, Protection, Replan, Requirement, Router, SharingParameters,
    plan_transmission, sharing_parameters,
};

#[cfg(test)]
mod tests;

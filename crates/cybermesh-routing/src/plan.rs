use std::collections::BTreeMap;

use cybermesh_trust::policy::DomainId;

use crate::graph::{Graph, NodeId};
use crate::paths::{Constraints, Disjointness, Path, RoutingError, disjoint_paths, usable};

/// How wrong or altered shares are handled at the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Shares are neither authenticated nor error-corrected: only eavesdropping is covered.
    None,
    /// Shares carry information-theoretic MACs (`cybermesh_trust::shares`): altered shares are
    /// rejected, so each tampered path costs one share.
    Authenticated,
    /// Shares are Reed-Solomon coded (`cybermesh_sharing::reconstruct_robust`): each tampered
    /// path costs two shares of redundancy.
    ReedSolomon,
}

/// What to survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// Domains the adversary may control (it reads and, if `tampering`, alters what crosses them).
    pub corrupt_domains: usize,
    /// Paths that may fail or drop shares on top of that.
    pub path_failures: usize,
    /// Whether corrupt domains may alter shares, not only read them.
    pub tampering: bool,
    pub protection: Protection,
}

/// Shamir parameters for sending one share per disjoint path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharingParameters {
    /// Shares, hence disjoint paths, needed.
    pub paths: usize,
    /// Threshold: more than the number of corrupt domains. `1` means no sharing is needed (no
    /// corrupt domain is assumed) and the message can travel unsplit.
    pub threshold: usize,
}

/// Parameters for `t` corrupt domains and `f` path failures.
///
/// Threshold `k = t + 1`, so that the `t` shares an adversary sees reveal nothing. Needed paths:
/// `k + f` without tampering; `k + t + f` with authenticated shares (each tampered path is one
/// rejected share, so `n - t - f >= k`); `k + 2t + f` with Reed-Solomon decoding (the bound
/// `2e + s <= n - k`). With `t` tampering and no protection the result would be wrong without any
/// error, so that is refused. These count shares needed under the stated model; they are
/// consequences of the sharing constructions, and the classical perfectly-secure-message-
/// transmission bounds (`2t + 1` paths with interaction, `3t + 1` without) are the literature
/// the numbers are consistent with (citations to be verified).
///
/// # Errors
/// [`RoutingError::UnprotectedTampering`].
pub fn sharing_parameters(r: &Requirement) -> Result<SharingParameters, RoutingError> {
    let t = r.corrupt_domains;
    let threshold = t + 1;
    let extra = if r.tampering {
        match r.protection {
            Protection::None => return Err(RoutingError::UnprotectedTampering),
            Protection::Authenticated => t,
            Protection::ReedSolomon => 2 * t,
        }
    } else {
        0
    };
    Ok(SharingParameters {
        paths: threshold + extra + r.path_failures,
        threshold,
    })
}

/// Paths chosen for a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub paths: Vec<Path>,
    pub params: SharingParameters,
    pub mode: Disjointness,
}

/// Choose the minimum-cost set of disjoint paths a requirement needs.
///
/// Only [`Disjointness::Domain`] makes the corrupt-domain count mean domains; with `Vertex` or
/// `Edge` the same numbers cover corrupt nodes or links.
///
/// # Errors
/// [`RoutingError::Insufficient`] if fewer than the needed paths exist, plus the errors of
/// [`sharing_parameters`] and [`disjoint_paths`].
pub fn plan_transmission(
    g: &Graph,
    s: NodeId,
    t: NodeId,
    req: &Requirement,
    c: &Constraints,
    mode: Disjointness,
) -> Result<Plan, RoutingError> {
    let params = sharing_parameters(req)?;
    let mut paths = disjoint_paths(g, s, t, mode, c, params.paths)?;
    if paths.len() < params.paths {
        return Err(RoutingError::Insufficient {
            found: paths.len(),
            needed: params.paths,
        });
    }
    paths.truncate(params.paths);
    Ok(Plan {
        paths,
        params,
        mode,
    })
}

/// Secret bytes reserved per link by one [`Router::allocate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub per_link: BTreeMap<(NodeId, NodeId), u64>,
}

/// What a re-plan changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replan {
    /// Paths of the old plan that are still in the new one.
    pub kept: usize,
    /// Paths that are new.
    pub replaced: usize,
}

/// A plan that tracks failures and secret budgets.
#[derive(Debug, Clone)]
pub struct Router {
    graph: Graph,
    s: NodeId,
    t: NodeId,
    req: Requirement,
    cons: Constraints,
    plan: Plan,
}

impl Router {
    /// Plan the first transmission.
    ///
    /// # Errors
    /// As [`plan_transmission`].
    pub fn new(
        graph: Graph,
        s: NodeId,
        t: NodeId,
        req: Requirement,
        cons: Constraints,
        mode: Disjointness,
    ) -> Result<Self, RoutingError> {
        let plan = plan_transmission(&graph, s, t, &req, &cons, mode)?;
        Ok(Self {
            graph,
            s,
            t,
            req,
            cons,
            plan,
        })
    }

    /// The current plan.
    #[must_use]
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// The graph with its current secret budgets.
    #[must_use]
    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    /// Report a link failed (both directions).
    pub fn fail_link(&mut self, a: NodeId, b: NodeId) {
        self.cons.fail_link(a, b);
    }

    /// Report a node failed or distrusted.
    pub fn fail_node(&mut self, n: NodeId) {
        self.cons.exclude_nodes.insert(n);
    }

    /// Treat a whole domain as adversarial from now on: nothing in it will be used.
    pub fn exclude_domain(&mut self, d: DomainId) {
        self.cons.exclude_domains.insert(d);
    }

    /// Indexes of plan paths that can no longer be used under the current failures, exclusions
    /// and budgets.
    #[must_use]
    pub fn broken(&self) -> Vec<usize> {
        self.plan
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| !p.hops().all(|(a, b)| usable(&self.graph, &self.cons, a, b)))
            .map(|(i, _)| i)
            .collect()
    }

    /// Recompute the plan under the current failures. On error the old plan is kept.
    ///
    /// # Errors
    /// As [`plan_transmission`].
    pub fn replan(&mut self) -> Result<Replan, RoutingError> {
        let new = plan_transmission(
            &self.graph,
            self.s,
            self.t,
            &self.req,
            &self.cons,
            self.plan.mode,
        )?;
        let kept = new
            .paths
            .iter()
            .filter(|p| self.plan.paths.contains(p))
            .count();
        let replaced = new.paths.len() - kept;
        self.plan = new;
        Ok(Replan { kept, replaced })
    }

    /// Spend `bytes_per_path` secret bytes on every hop of every path in the plan, all or
    /// nothing.
    ///
    /// # Errors
    /// [`RoutingError::Exhausted`] for the first link that cannot carry its total demand; no
    /// budget is changed.
    pub fn allocate(&mut self, bytes_per_path: u64) -> Result<Allocation, RoutingError> {
        let mut per_link: BTreeMap<(NodeId, NodeId), u64> = BTreeMap::new();
        for p in &self.plan.paths {
            for hop in p.hops() {
                let e = per_link.entry(hop).or_default();
                *e = e.saturating_add(bytes_per_path);
            }
        }
        for (&(a, b), &need) in &per_link {
            let have = self.graph.link(a, b).map_or(0, |l| l.secret_bytes);
            if have < need {
                return Err(RoutingError::Exhausted {
                    from: a,
                    to: b,
                    have,
                    need,
                });
            }
        }
        for (&(a, b), &need) in &per_link {
            if let Some(l) = self.graph.links.get_mut(&a).and_then(|m| m.get_mut(&b)) {
                l.secret_bytes = l.secret_bytes.saturating_sub(need);
            }
        }
        Ok(Allocation { per_link })
    }

    /// One provisioning tick on every link.
    pub fn replenish(&mut self) {
        self.graph.replenish();
    }
}

use std::collections::{BTreeMap, BTreeSet};

use cybermesh_routing::{
    Constraints, Disjointness, Graph, NodeId, Plan, Protection, Requirement, allocate_paths,
    plan_transmission, sharing_parameters, wire_secret_flow,
};
use cybermesh_trust::policy::DomainId;

use crate::report::Report;
use crate::rng::SimRng;
use crate::scenario::{AdversaryCfg, RECORD_OVERHEAD, Scenario, SimError};

type Link = (NodeId, NodeId);

struct Topology {
    graph: Graph,
    /// Undirected links, each once, smaller id first.
    links: Vec<Link>,
    members: BTreeMap<DomainId, Vec<NodeId>>,
}

fn norm(a: NodeId, b: NodeId) -> Link {
    if a <= b { (a, b) } else { (b, a) }
}

/// Participants spread over domains; a ring inside every domain (so each domain is internally
/// connected and domain contraction is exact), a ring across all participants for connectivity,
/// and random cross-domain links.
fn build(sc: &Scenario, rng: &mut SimRng) -> Topology {
    let n = sc.participants;
    let mut dom: Vec<u32> = (0..n)
        .map(|i| {
            if i < sc.domains {
                i as u32
            } else {
                rng.below(sc.domains as u64) as u32
            }
        })
        .collect();
    // Spread the guaranteed one-per-domain nodes around so ids carry no pattern.
    for i in (1..n).rev() {
        dom.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let id = |i: usize| NodeId(i as u32 + 1);
    let mut graph = Graph::new();
    let mut members: BTreeMap<DomainId, Vec<NodeId>> = BTreeMap::new();
    for (i, &d) in dom.iter().enumerate() {
        graph.add_node(id(i), DomainId(d));
        members.entry(DomainId(d)).or_default().push(id(i));
    }
    let mut seen: BTreeSet<Link> = BTreeSet::new();
    let mut link = |graph: &mut Graph, a: NodeId, b: NodeId, lat: u32| {
        if a != b && seen.insert(norm(a, b)) {
            graph.add_link(a, b, lat, sc.initial_secret, sc.initial_secret);
            graph.set_replenish(a, b, sc.replenish_per_tick, sc.replenish_per_tick);
        }
    };
    for m in members.values() {
        if m.len() > 1 {
            for w in 0..m.len() {
                link(&mut graph, m[w], m[(w + 1) % m.len()], 1);
            }
        }
    }
    for i in 0..n {
        let (a, b) = (id(i), id((i + 1) % n));
        if graph.domain(a) != graph.domain(b) {
            let lat = rng.range(sc.latency_min_ms, sc.latency_max_ms);
            link(&mut graph, a, b, lat);
        }
    }
    for i in 0..n {
        for _ in 0..sc.extra_links_per_node {
            let j = rng.below(n as u64) as usize;
            if dom[i] != dom[j] {
                let lat = rng.range(sc.latency_min_ms, sc.latency_max_ms);
                link(&mut graph, id(i), id(j), lat);
            }
        }
    }
    let mut links: Vec<Link> = seen.into_iter().collect();
    links.sort();
    Topology {
        graph,
        links,
        members,
    }
}

fn requirement(sc: &Scenario) -> Requirement {
    Requirement {
        corrupt_domains: sc.requirement.corrupt_domains,
        path_failures: sc.requirement.path_failures,
        tampering: sc.requirement.tampering,
        protection: sc.requirement.protection.into(),
    }
}

fn pick_pairs(g: &Graph, sessions: usize, rng: &mut SimRng) -> Vec<(NodeId, NodeId)> {
    let nodes: Vec<NodeId> = g.nodes().collect();
    let mut pairs = Vec::with_capacity(sessions);
    while pairs.len() < sessions {
        let (a, b) = (
            nodes[rng.below(nodes.len() as u64) as usize],
            nodes[rng.below(nodes.len() as u64) as usize],
        );
        if a != b && g.domain(a) != g.domain(b) {
            pairs.push((a, b));
        }
    }
    pairs
}

fn random_domains(all: &[DomainId], c: usize, rng: &mut SimRng) -> BTreeSet<DomainId> {
    let mut pool = all.to_vec();
    let mut out = BTreeSet::new();
    while out.len() < c.min(pool.len()) {
        let i = rng.below(pool.len() as u64) as usize;
        out.insert(pool.swap_remove(i));
    }
    out
}

struct Session {
    s: NodeId,
    t: NodeId,
    plan: Option<Plan>,
    down_since: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Delivered,
    BreachedPaths,
    BreachedEndpoint,
    NoPlan,
    Starved,
    Lost,
}

/// Run one scenario.
///
/// Each tick: the adversary may move; links and domains fail and recover; secret budgets are
/// replenished; then every session sends one message. Plans are made with what the router **knows**
/// (failures older than one tick, corrupt domains older than `detect_ticks`) and judged against
/// the **truth**.
///
/// # Errors
/// [`SimError::Invalid`] for a bad scenario, [`SimError::Routing`] if the requirement itself is
/// unsatisfiable (tampering with no protection).
pub fn simulate(sc: &Scenario) -> Result<Report, SimError> {
    sc.validate()?;
    let req = requirement(sc);
    let params = sharing_parameters(&req).map_err(|e| SimError::Routing(e.to_string()))?;
    let mut master = SimRng::new(sc.seed);
    let (mut topo_rng, mut dyn_rng, mut sess_rng) =
        (master.fork(1), master.fork(2), master.fork(3));
    let Topology {
        mut graph,
        links,
        members,
    } = build(sc, &mut topo_rng);
    let all_domains: Vec<DomainId> = members.keys().copied().collect();
    let mut sessions: Vec<Session> = pick_pairs(&graph, sc.sessions, &mut sess_rng)
        .into_iter()
        .map(|(s, t)| Session {
            s,
            t,
            plan: None,
            down_since: None,
        })
        .collect();
    let bytes_per_path = sc.msg_bytes + RECORD_OVERHEAD;

    let mut report = Report {
        paths_per_message: params.paths,
        ..Report::default()
    };
    let mut link_down_until: BTreeMap<Link, u32> = BTreeMap::new();
    let mut outage_until: BTreeMap<DomainId, u32> = BTreeMap::new();
    let mut prev_down: BTreeSet<Link> = BTreeSet::new();
    let mut corrupt: BTreeSet<DomainId> = match sc.adversary {
        AdversaryCfg::None => BTreeSet::new(),
        AdversaryCfg::Static { corrupt_domains }
        | AdversaryCfg::Mobile {
            corrupt_domains, ..
        } => random_domains(&all_domains, corrupt_domains, &mut dyn_rng),
    };
    let mut corrupt_age: BTreeMap<DomainId, u32> = BTreeMap::new();

    for tick in 0..sc.ticks {
        // 1. What the router knows: last tick's failures.
        let known_failed = prev_down.clone();
        // 2. Adversary and detection.
        if let AdversaryCfg::Mobile {
            corrupt_domains,
            move_prob,
        } = sc.adversary
            && tick > 0
            && dyn_rng.chance(move_prob)
        {
            corrupt = random_domains(&all_domains, corrupt_domains, &mut dyn_rng);
        }
        corrupt_age.retain(|d, _| corrupt.contains(d));
        for d in &corrupt {
            *corrupt_age.entry(*d).or_insert(0) += 1;
        }
        let known_corrupt: BTreeSet<DomainId> = corrupt_age
            .iter()
            .filter(|&(_, &age)| age > sc.detect_ticks)
            .map(|(&d, _)| d)
            .collect();
        // 3. Failures this tick (truth).
        outage_until.retain(|_, &mut u| u > tick);
        link_down_until.retain(|_, &mut u| u > tick);
        for &l in &links {
            if !link_down_until.contains_key(&l) && dyn_rng.chance(sc.link_failure_prob) {
                link_down_until.insert(l, tick + sc.link_repair_ticks.max(1));
            }
        }
        for d in &all_domains {
            if !outage_until.contains_key(d) && dyn_rng.chance(sc.domain_outage_prob) {
                outage_until.insert(*d, tick + sc.outage_ticks.max(1));
            }
        }
        let mut down: BTreeSet<Link> = BTreeSet::new();
        for &(a, b) in link_down_until.keys() {
            down.insert((a, b));
            down.insert((b, a));
        }
        for d in outage_until.keys() {
            for &n in &members[d] {
                for &b in graph.links_of(n) {
                    down.insert((n, b));
                    down.insert((b, n));
                }
            }
        }
        // 4. Provisioning.
        if tick > 0 {
            graph.replenish();
        }
        // 5. Sessions.
        let cons = Constraints {
            exclude_domains: known_corrupt.clone(),
            failed_links: known_failed,
            msg_bytes: bytes_per_path,
            scarcity_weight: sc.scarcity_weight,
            ..Constraints::default()
        };
        let mut delivered_now = 0u32;
        for sess in &mut sessions {
            report.attempted += 1;
            let need = sess
                .plan
                .as_ref()
                .is_none_or(|p| !p.paths.iter().all(|x| x.is_usable(&graph, &cons)));
            if need {
                report.replans += 1;
                sess.plan =
                    plan_transmission(&graph, sess.s, sess.t, &req, &cons, Disjointness::Domain)
                        .ok();
            }
            let outcome = match sess.plan.clone() {
                None => Outcome::NoPlan,
                Some(plan) => match allocate_paths(&mut graph, &plan.paths, bytes_per_path) {
                    Err(_) => {
                        sess.plan = None;
                        Outcome::Starved
                    }
                    Ok(_) => {
                        report.wire_bytes += plan.paths.len() as u64 * bytes_per_path;
                        report.secret_consumed += plan
                            .paths
                            .iter()
                            .map(|p| p.nodes.len().saturating_sub(1) as u64)
                            .sum::<u64>()
                            * bytes_per_path;
                        judge(
                            &graph,
                            sess,
                            &plan,
                            &down,
                            &corrupt,
                            &req,
                            plan.params.threshold,
                        )
                    }
                },
            };
            match outcome {
                Outcome::Delivered => {
                    report.delivered += 1;
                    report.payload_bytes += sc.msg_bytes;
                    delivered_now += 1;
                }
                Outcome::BreachedPaths => report.breached_paths += 1,
                Outcome::BreachedEndpoint => report.breached_endpoint += 1,
                Outcome::NoPlan => report.no_plan += 1,
                Outcome::Starved => report.starved += 1,
                Outcome::Lost => report.lost += 1,
            }
            if outcome == Outcome::Delivered {
                if let Some(since) = sess.down_since.take() {
                    let d = tick - since;
                    report.recoveries += 1;
                    report.recovery_total_ticks += u64::from(d);
                    report.recovery_max_ticks = report.recovery_max_ticks.max(d);
                }
            } else if sess.down_since.is_none() {
                sess.down_since = Some(tick);
            }
        }
        report.delivered_by_tick.push(delivered_now);
        prev_down = down;
    }
    Ok(report)
}

/// Judge one message against the truth.
fn judge(
    g: &Graph,
    sess: &Session,
    plan: &Plan,
    down: &BTreeSet<Link>,
    corrupt: &BTreeSet<DomainId>,
    req: &Requirement,
    k: usize,
) -> Outcome {
    let (ds, dt) = (g.domain(sess.s), g.domain(sess.t));
    if ds.is_some_and(|d| corrupt.contains(&d)) || dt.is_some_and(|d| corrupt.contains(&d)) {
        return Outcome::BreachedEndpoint;
    }
    let n = plan.paths.len();
    let (mut lost, mut touched, mut tampered) = (0usize, 0usize, 0usize);
    for p in &plan.paths {
        let is_lost = p.hops().any(|h| down.contains(&h));
        let is_touched = p
            .domains(g)
            .iter()
            .any(|d| corrupt.contains(d) && Some(*d) != ds && Some(*d) != dt);
        lost += usize::from(is_lost);
        touched += usize::from(is_touched);
        tampered += usize::from(is_touched && !is_lost && req.tampering);
    }
    if touched >= k {
        return Outcome::BreachedPaths;
    }
    let ok = match req.protection {
        Protection::ReedSolomon => n >= lost + k + 2 * tampered,
        _ => n >= lost + tampered + k,
    };
    if ok {
        Outcome::Delivered
    } else {
        Outcome::Lost
    }
}

/// Result of [`drain_bound`].
#[derive(Debug, Clone, PartialEq)]
pub struct Drain {
    /// Max-flow of the initial secret budgets between the pair (wire bytes).
    pub bound: u64,
    /// Share bytes actually sent before the session could no longer be planned.
    pub measured: u64,
    pub sends: u64,
    pub paths: usize,
}

impl Drain {
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.bound == 0 {
            0.0
        } else {
            self.measured as f64 / self.bound as f64
        }
    }
}

/// Send between one pair, with no replenishment, until the router can no longer plan, and
/// compare the share bytes sent with `wire_secret_flow` on the initial budgets. Every successful
/// send spends a unit of secret on every hop of `n` disjoint paths, so the paths summed are a
/// feasible flow and `measured <= bound` must hold.
///
/// # Errors
/// As [`simulate`].
pub fn drain_bound(sc: &Scenario) -> Result<Drain, SimError> {
    sc.validate()?;
    let req = requirement(sc);
    let params = sharing_parameters(&req).map_err(|e| SimError::Routing(e.to_string()))?;
    let mut master = SimRng::new(sc.seed);
    let mut topo_rng = master.fork(1);
    let mut sess_rng = master.fork(3);
    let Topology { mut graph, .. } = build(sc, &mut topo_rng);
    let (s, t) = pick_pairs(&graph, 1, &mut sess_rng)[0];
    let bound = wire_secret_flow(&graph, s, t, &Constraints::default())
        .map_err(|e| SimError::Routing(e.to_string()))?;
    let bytes_per_path = sc.msg_bytes + RECORD_OVERHEAD;
    let cons = Constraints {
        msg_bytes: bytes_per_path,
        scarcity_weight: sc.scarcity_weight,
        ..Constraints::default()
    };
    let (mut sends, mut measured) = (0u64, 0u64);
    while let Ok(plan) = plan_transmission(&graph, s, t, &req, &cons, Disjointness::Domain) {
        if allocate_paths(&mut graph, &plan.paths, bytes_per_path).is_err() {
            break;
        }
        sends += 1;
        measured += plan.paths.len() as u64 * bytes_per_path;
        if sends > 5_000_000 {
            break;
        }
    }
    Ok(Drain {
        bound,
        measured,
        sends,
        paths: params.paths,
    })
}

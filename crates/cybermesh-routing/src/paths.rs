use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use cybermesh_trust::policy::DomainId;

use crate::flow::{Flow, INF};
use crate::graph::{Graph, NodeId};

/// What "disjoint" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disjointness {
    /// No link used by two paths (nodes may be shared).
    Edge,
    /// No node, other than the endpoints, on two paths.
    Vertex,
    /// No administrative domain, other than those of the two endpoints, on two paths.
    Domain,
}

/// Limits and preferences for a routing query.
#[derive(Debug, Clone, Default)]
pub struct Constraints {
    /// Domains the adversary is assumed to control: nothing in them is used.
    pub exclude_domains: BTreeSet<DomainId>,
    /// Individual nodes not to use.
    pub exclude_nodes: BTreeSet<NodeId>,
    /// Links reported failed (stored in both directions by [`Constraints::fail_link`]).
    pub failed_links: BTreeSet<(NodeId, NodeId)>,
    /// A hop is usable only if its secret budget can carry this many bytes (and is not empty).
    pub msg_bytes: u64,
    /// Extra cost for hops with a small budget: `weight * msg_bytes * 1000 / budget`.
    pub scarcity_weight: u64,
}

impl Constraints {
    /// Mark the link between `a` and `b` failed, in both directions.
    pub fn fail_link(&mut self, a: NodeId, b: NodeId) {
        self.failed_links.insert((a, b));
        self.failed_links.insert((b, a));
    }
}

/// Routing failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoutingError {
    #[error("unknown node {0:?}")]
    UnknownNode(NodeId),
    #[error("source and destination are the same node")]
    SameEndpoints,
    #[error("endpoint {0:?} is excluded or in an excluded domain")]
    EndpointExcluded(NodeId),
    #[error("domain {0:?} cannot connect its own nodes with usable links")]
    DomainDisconnected(DomainId),
    #[error("only {found} disjoint paths exist, {needed} needed")]
    Insufficient { found: usize, needed: usize },
    #[error("tampering must be covered by authenticated shares or error correction")]
    UnprotectedTampering,
    #[error("link {from:?} -> {to:?} has {have} secret bytes, {need} needed")]
    Exhausted {
        from: NodeId,
        to: NodeId,
        have: u64,
        need: u64,
    },
}

/// A path as a node sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub nodes: Vec<NodeId>,
    pub latency_ms: u64,
}

impl Path {
    /// The directed hops.
    pub fn hops(&self) -> impl Iterator<Item = (NodeId, NodeId)> + '_ {
        self.nodes.windows(2).map(|w| (w[0], w[1]))
    }
    /// Domains the path passes through.
    #[must_use]
    pub fn domains(&self, g: &Graph) -> BTreeSet<DomainId> {
        self.nodes.iter().filter_map(|&n| g.domain(n)).collect()
    }
}

pub(crate) fn excluded(g: &Graph, c: &Constraints, n: NodeId) -> bool {
    c.exclude_nodes.contains(&n) || g.domain(n).is_some_and(|d| c.exclude_domains.contains(&d))
}

pub(crate) fn usable(g: &Graph, c: &Constraints, a: NodeId, b: NodeId) -> bool {
    !excluded(g, c, a)
        && !excluded(g, c, b)
        && !c.failed_links.contains(&(a, b))
        && g.link(a, b)
            .is_some_and(|l| l.secret_bytes >= c.msg_bytes.max(1))
}

fn cost(g: &Graph, c: &Constraints, a: NodeId, b: NodeId) -> i64 {
    let Some(l) = g.link(a, b) else {
        return INF / 8;
    };
    let scarcity = c
        .scarcity_weight
        .saturating_mul(c.msg_bytes.saturating_mul(1000))
        .checked_div(l.secret_bytes.max(1))
        .unwrap_or(0);
    i64::from(l.latency_ms).saturating_add(i64::try_from(scarcity).unwrap_or(i64::MAX / 8))
}

/// Cheapest route from `x` to `y` through nodes of domain `d` only.
fn internal_route(
    g: &Graph,
    c: &Constraints,
    d: DomainId,
    x: NodeId,
    y: NodeId,
) -> Option<Vec<NodeId>> {
    let mut dist: BTreeMap<NodeId, i64> = BTreeMap::new();
    let mut prev: BTreeMap<NodeId, NodeId> = BTreeMap::new();
    let mut heap = BinaryHeap::new();
    dist.insert(x, 0);
    heap.push(Reverse((0i64, x)));
    while let Some(Reverse((du, u))) = heap.pop() {
        if u == y {
            break;
        }
        if dist.get(&u).is_some_and(|&b| du > b) {
            continue;
        }
        for (&v, _) in g.links.get(&u).into_iter().flatten() {
            if g.domain(v) != Some(d) || !usable(g, c, u, v) {
                continue;
            }
            let nd = du + cost(g, c, u, v);
            if dist.get(&v).is_none_or(|&b| nd < b) {
                dist.insert(v, nd);
                prev.insert(v, u);
                heap.push(Reverse((nd, v)));
            }
        }
    }
    dist.get(&y)?;
    let mut route = vec![y];
    let mut cur = y;
    while cur != x {
        cur = *prev.get(&cur)?;
        route.push(cur);
    }
    route.reverse();
    Some(route)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    N(NodeId),
    D(DomainId),
}

/// Up to `want` minimum-total-cost disjoint paths from `s` to `t`, cheapest first. Fewer are
/// returned when fewer exist; the caller decides whether that is enough. Cost is latency plus the
/// scarcity term.
///
/// # Errors
/// [`RoutingError::UnknownNode`], [`RoutingError::SameEndpoints`],
/// [`RoutingError::EndpointExcluded`], [`RoutingError::DomainDisconnected`].
pub fn disjoint_paths(
    g: &Graph,
    s: NodeId,
    t: NodeId,
    mode: Disjointness,
    c: &Constraints,
    want: usize,
) -> Result<Vec<Path>, RoutingError> {
    for n in [s, t] {
        if g.domain(n).is_none() {
            return Err(RoutingError::UnknownNode(n));
        }
        if excluded(g, c, n) {
            return Err(RoutingError::EndpointExcluded(n));
        }
    }
    if s == t {
        return Err(RoutingError::SameEndpoints);
    }
    let (ds, dt) = (g.domain(s), g.domain(t));
    let key = |n: NodeId| match (mode, g.domain(n)) {
        (Disjointness::Domain, Some(d)) if Some(d) != ds && Some(d) != dt => Key::D(d),
        _ => Key::N(n),
    };
    let mut index: BTreeMap<Key, usize> = BTreeMap::new();
    for n in g.nodes().filter(|&n| !excluded(g, c, n)) {
        let k = key(n);
        let next = index.len();
        index.entry(k).or_insert(next);
    }
    let (ks, kt) = (Key::N(s), Key::N(t));
    let (vin, vout) = (|i: usize| 2 * i, |i: usize| 2 * i + 1);
    let mut f = Flow::new(2 * index.len());
    for (&k, &i) in &index {
        let cap = if mode == Disjointness::Edge || k == ks || k == kt {
            INF
        } else {
            1
        };
        f.add_edge(vin(i), vout(i), cap, 0);
    }
    // Every usable directed link between different super nodes: (flow edge, a, b).
    let mut link_edges: Vec<(usize, NodeId, NodeId)> = Vec::new();
    for (&a, m) in &g.links {
        for &b in m.keys() {
            if !usable(g, c, a, b) {
                continue;
            }
            let (ka, kb) = (key(a), key(b));
            if ka == kb {
                continue;
            }
            let (Some(&ia), Some(&ib)) = (index.get(&ka), index.get(&kb)) else {
                continue;
            };
            link_edges.push((f.add_edge(vout(ia), vin(ib), 1, cost(g, c, a, b)), a, b));
        }
    }
    let limit = i64::try_from(want).unwrap_or(i64::MAX / 8);
    let (is, it) = (index[&ks], index[&kt]);
    f.run(vin(is), vout(it), limit);

    // Decompose the flow into paths.
    let mut outgoing: BTreeMap<Key, Vec<(NodeId, NodeId)>> = BTreeMap::new();
    for &(e, a, b) in &link_edges {
        if f.flow_on(e) > 0 {
            outgoing.entry(key(a)).or_default().push((a, b));
        }
    }
    let mut paths = Vec::new();
    while let Some(first) = outgoing.get_mut(&ks).and_then(Vec::pop) {
        let mut hops = vec![first];
        while key(hops[hops.len() - 1].1) != kt {
            let at = key(hops[hops.len() - 1].1);
            match outgoing.get_mut(&at).and_then(Vec::pop) {
                Some(next) => hops.push(next),
                None => break,
            }
        }
        if key(hops[hops.len() - 1].1) != kt {
            continue; // a dangling remnant: cannot happen for a valid flow
        }
        // Stitch real nodes, inserting the internal route inside a contracted domain.
        let mut nodes = vec![s];
        for (a, b) in hops {
            let last = nodes[nodes.len() - 1];
            if last != a {
                let d = g.domain(a).ok_or(RoutingError::UnknownNode(a))?;
                let route =
                    internal_route(g, c, d, last, a).ok_or(RoutingError::DomainDisconnected(d))?;
                nodes.extend(route.into_iter().skip(1));
            }
            nodes.push(b);
        }
        let latency_ms = nodes
            .windows(2)
            .filter_map(|w| g.link(w[0], w[1]))
            .map(|l| u64::from(l.latency_ms))
            .sum();
        paths.push(Path { nodes, latency_ms });
    }
    paths.sort_by(|x, y| {
        x.latency_ms
            .cmp(&y.latency_ms)
            .then_with(|| x.nodes.cmp(&y.nodes))
    });
    Ok(paths)
}

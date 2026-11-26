use crate::flow::Flow;
use crate::graph::{Graph, NodeId};
use crate::paths::{Constraints, RoutingError, excluded};

const CAP_CLAMP: u64 = 1 << 50;

/// Maximum total **wire bytes** that per-hop one-time-pad forwarding can move from `s` to `t`
/// given every link's remaining secret budget: a plain max-flow with the budgets as capacities,
/// over the links the constraints leave usable (`msg_bytes` is ignored).
///
/// This is a bound for one specific scheme (every hop pads what it forwards, no coding across
/// paths). It is **not** the information-theoretic secret capacity of the network, which is an open
/// research question, and it counts wire bytes, not message bytes: sharing a message over `n`
/// paths puts `n` times its length on the wire. Budgets are clamped at 2^50 bytes each.
///
/// # Errors
/// [`RoutingError::UnknownNode`], [`RoutingError::SameEndpoints`], [`RoutingError::EndpointExcluded`].
pub fn wire_secret_flow(
    g: &Graph,
    s: NodeId,
    t: NodeId,
    c: &Constraints,
) -> Result<u64, RoutingError> {
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
    let ids: Vec<NodeId> = g.nodes().filter(|&n| !excluded(g, c, n)).collect();
    let at = |n: NodeId| ids.iter().position(|&x| x == n);
    let mut f = Flow::new(ids.len());
    for (&a, m) in &g.links {
        for (&b, l) in m {
            if c.failed_links.contains(&(a, b)) || l.secret_bytes == 0 {
                continue;
            }
            if let (Some(ia), Some(ib)) = (at(a), at(b)) {
                f.add_edge(
                    ia,
                    ib,
                    i64::try_from(l.secret_bytes.min(CAP_CLAMP)).unwrap_or(i64::MAX / 8),
                    0,
                );
            }
        }
    }
    let flow = f.run(at(s).unwrap_or(0), at(t).unwrap_or(0), i64::MAX / 8);
    Ok(u64::try_from(flow).unwrap_or(0))
}

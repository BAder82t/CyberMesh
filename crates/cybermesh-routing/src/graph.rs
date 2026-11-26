use std::collections::BTreeMap;

use cybermesh_trust::policy::DomainId;
pub use cybermesh_trust::policy::ParticipantId as NodeId;

/// One direction of a link: latency and the secret bytes left in the pool that protects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// Latency in milliseconds (at least 1 so that costs are positive).
    pub latency_ms: u32,
    /// Secret bytes left for traffic in this direction (one-time-pad material).
    pub secret_bytes: u64,
    /// Secret bytes provisioned per [`Graph::replenish`] tick.
    pub replenish: u64,
}

/// Participants, their domains and directed links.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub(crate) domain_of: BTreeMap<NodeId, DomainId>,
    pub(crate) links: BTreeMap<NodeId, BTreeMap<NodeId, Link>>,
}

impl Graph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or move) a participant to a domain.
    pub fn add_node(&mut self, n: NodeId, d: DomainId) {
        self.domain_of.insert(n, d);
        self.links.entry(n).or_default();
    }

    /// Domain of a node.
    #[must_use]
    pub fn domain(&self, n: NodeId) -> Option<DomainId> {
        self.domain_of.get(&n).copied()
    }

    /// All nodes.
    pub fn nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.domain_of.keys().copied()
    }

    /// Add a bidirectional link with separate secret budgets per direction.
    ///
    /// Returns `false` (and adds nothing) if either endpoint is unknown or `a == b`.
    pub fn add_link(
        &mut self,
        a: NodeId,
        b: NodeId,
        latency_ms: u32,
        secret_ab: u64,
        secret_ba: u64,
    ) -> bool {
        if a == b || !self.domain_of.contains_key(&a) || !self.domain_of.contains_key(&b) {
            return false;
        }
        let l = |secret_bytes| Link {
            latency_ms: latency_ms.max(1),
            secret_bytes,
            replenish: 0,
        };
        self.links.entry(a).or_default().insert(b, l(secret_ab));
        self.links.entry(b).or_default().insert(a, l(secret_ba));
        true
    }

    /// Set how many secret bytes each direction of a link gains per [`Graph::replenish`].
    pub fn set_replenish(&mut self, a: NodeId, b: NodeId, ab: u64, ba: u64) {
        if let Some(l) = self.links.get_mut(&a).and_then(|m| m.get_mut(&b)) {
            l.replenish = ab;
        }
        if let Some(l) = self.links.get_mut(&b).and_then(|m| m.get_mut(&a)) {
            l.replenish = ba;
        }
    }

    /// The nodes `n` has a link to.
    pub fn links_of(&self, n: NodeId) -> impl Iterator<Item = &NodeId> + '_ {
        self.links.get(&n).into_iter().flat_map(BTreeMap::keys)
    }

    /// The directed link `a -> b`.
    #[must_use]
    pub fn link(&self, a: NodeId, b: NodeId) -> Option<&Link> {
        self.links.get(&a).and_then(|m| m.get(&b))
    }

    /// One provisioning tick: every directed link gains its `replenish` secret bytes.
    pub fn replenish(&mut self) {
        for m in self.links.values_mut() {
            for l in m.values_mut() {
                l.secret_bytes = l.secret_bytes.saturating_add(l.replenish);
            }
        }
    }
}

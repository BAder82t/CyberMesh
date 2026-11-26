#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_range_loop
)]
use super::*;
use cybermesh_trust::policy::DomainId;
use std::collections::BTreeSet;

fn n(i: u32) -> NodeId {
    NodeId(i)
}
fn d(i: u32) -> DomainId {
    DomainId(i)
}

/// (node, domain) pairs and (a, b, latency) links with 1000 secret bytes each way.
fn build(nodes: &[(u32, u32)], links: &[(u32, u32, u32)]) -> Graph {
    let mut g = Graph::new();
    for &(id, dom) in nodes {
        g.add_node(n(id), d(dom));
    }
    for &(a, b, lat) in links {
        assert!(g.add_link(n(a), n(b), lat, 1000, 1000));
    }
    g
}

fn count(g: &Graph, s: u32, t: u32, mode: Disjointness, c: &Constraints) -> usize {
    disjoint_paths(g, n(s), n(t), mode, c, usize::MAX)
        .unwrap()
        .len()
}

/// xorshift for deterministic random graphs. Test fixture only.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[test]
fn diamond_has_two_disjoint_paths_in_every_mode_cheapest_first() {
    let g = build(
        &[(1, 1), (2, 2), (3, 3), (4, 4)],
        &[(1, 2, 10), (2, 4, 10), (1, 3, 30), (3, 4, 30)],
    );
    for mode in [
        Disjointness::Edge,
        Disjointness::Vertex,
        Disjointness::Domain,
    ] {
        let p = disjoint_paths(&g, n(1), n(4), mode, &Constraints::default(), 5).unwrap();
        assert_eq!(p.len(), 2, "{mode:?}");
        assert_eq!(p[0].nodes, vec![n(1), n(2), n(4)]);
        assert_eq!(p[0].latency_ms, 20);
        assert_eq!(p[1].latency_ms, 60);
    }
    // Asking for fewer returns the cheapest.
    let one = disjoint_paths(
        &g,
        n(1),
        n(4),
        Disjointness::Vertex,
        &Constraints::default(),
        1,
    )
    .unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].latency_ms, 20);
}

#[test]
fn edge_vertex_and_domain_disjointness_differ() {
    // Edge-disjoint 2, vertex-disjoint 1: both routes pass through node 5.
    let g = build(
        &[(1, 1), (2, 2), (3, 3), (5, 5), (6, 6), (7, 7), (9, 9)],
        &[
            (1, 2, 1),
            (1, 3, 1),
            (2, 5, 1),
            (3, 5, 1),
            (5, 6, 1),
            (5, 7, 1),
            (6, 9, 1),
            (7, 9, 1),
        ],
    );
    let c = Constraints::default();
    assert_eq!(count(&g, 1, 9, Disjointness::Edge, &c), 2);
    assert_eq!(count(&g, 1, 9, Disjointness::Vertex, &c), 1);
    // Two relays in ONE domain: vertex-disjoint 2, domain-disjoint 1.
    let g = build(
        &[(1, 1), (2, 7), (3, 7), (4, 4)],
        &[(1, 2, 1), (1, 3, 1), (2, 4, 1), (3, 4, 1)],
    );
    assert_eq!(count(&g, 1, 4, Disjointness::Vertex, &c), 2);
    assert_eq!(count(&g, 1, 4, Disjointness::Domain, &c), 1);
}

#[test]
fn a_contracted_domain_is_stitched_with_its_internal_route_or_fails_closed() {
    // s -> a, b -> t where a and b are both in domain 5 and linked: path s,a,b,t.
    let g = build(
        &[(1, 1), (2, 5), (3, 5), (4, 4)],
        &[(1, 2, 1), (2, 3, 7), (3, 4, 1)],
    );
    let p = disjoint_paths(
        &g,
        n(1),
        n(4),
        Disjointness::Domain,
        &Constraints::default(),
        3,
    )
    .unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].nodes, vec![n(1), n(2), n(3), n(4)]);
    assert_eq!(p[0].latency_ms, 9);
    assert_eq!(p[0].domains(&g), [d(1), d(5), d(4)].into_iter().collect());
    // Without the internal link the domain cannot connect its own nodes.
    let g = build(&[(1, 1), (2, 5), (3, 5), (4, 4)], &[(1, 2, 1), (3, 4, 1)]);
    assert_eq!(
        disjoint_paths(
            &g,
            n(1),
            n(4),
            Disjointness::Domain,
            &Constraints::default(),
            3
        )
        .unwrap_err(),
        RoutingError::DomainDisconnected(d(5))
    );
    // The endpoints' own domains are not contracted: two relays in the source's domain are two
    // separate nodes and both can carry a path.
    let g = build(
        &[(1, 1), (2, 1), (3, 1), (5, 2), (6, 3), (4, 4)],
        &[
            (1, 2, 1),
            (1, 3, 1),
            (2, 5, 1),
            (3, 6, 1),
            (5, 4, 1),
            (6, 4, 1),
        ],
    );
    assert_eq!(
        count(&g, 1, 4, Disjointness::Domain, &Constraints::default()),
        2
    );
}

#[test]
fn exclusions_failures_and_budgets_remove_routes() {
    let g = build(
        &[(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)],
        &[
            (1, 2, 1),
            (2, 5, 1),
            (1, 3, 1),
            (3, 5, 1),
            (1, 4, 1),
            (4, 5, 1),
        ],
    );
    let m = Disjointness::Domain;
    assert_eq!(count(&g, 1, 5, m, &Constraints::default()), 3);
    let mut c = Constraints::default();
    c.exclude_domains.insert(d(3));
    assert_eq!(count(&g, 1, 5, m, &c), 2);
    c.exclude_nodes.insert(n(4));
    assert_eq!(count(&g, 1, 5, m, &c), 1);
    let mut c = Constraints::default();
    c.fail_link(n(2), n(5));
    assert_eq!(count(&g, 1, 5, m, &c), 2);
    // Excluding an endpoint's domain is an error, not an empty answer.
    let mut c = Constraints::default();
    c.exclude_domains.insert(d(5));
    assert_eq!(
        disjoint_paths(&g, n(1), n(5), m, &c, 3).unwrap_err(),
        RoutingError::EndpointExcluded(n(5))
    );
    // Other structural errors.
    let c = Constraints::default();
    assert_eq!(
        disjoint_paths(&g, n(1), n(1), m, &c, 3).unwrap_err(),
        RoutingError::SameEndpoints
    );
    assert_eq!(
        disjoint_paths(&g, n(1), n(99), m, &c, 3).unwrap_err(),
        RoutingError::UnknownNode(n(99))
    );
    // A hop whose secret budget cannot carry the message is not usable; an empty one never is.
    let mut g2 = g.clone();
    g2.links
        .get_mut(&n(1))
        .unwrap()
        .get_mut(&n(2))
        .unwrap()
        .secret_bytes = 50;
    let big = Constraints {
        msg_bytes: 100,
        ..Constraints::default()
    };
    assert_eq!(count(&g2, 1, 5, m, &big), 2);
    assert_eq!(
        count(
            &g2,
            1,
            5,
            m,
            &Constraints {
                msg_bytes: 10,
                ..Constraints::default()
            }
        ),
        3
    );
    g2.links
        .get_mut(&n(1))
        .unwrap()
        .get_mut(&n(2))
        .unwrap()
        .secret_bytes = 0;
    assert_eq!(count(&g2, 1, 5, m, &Constraints::default()), 2);
}

#[test]
fn scarcity_steers_toward_links_with_more_secret_left() {
    // Same latency; the route through 3 has far more budget left.
    let mut g = build(
        &[(1, 1), (2, 2), (3, 3), (4, 4)],
        &[(1, 2, 5), (2, 4, 5), (1, 3, 5), (3, 4, 5)],
    );
    g.links
        .get_mut(&n(1))
        .unwrap()
        .get_mut(&n(2))
        .unwrap()
        .secret_bytes = 150;
    g.links
        .get_mut(&n(1))
        .unwrap()
        .get_mut(&n(3))
        .unwrap()
        .secret_bytes = 100_000;
    let c = Constraints {
        msg_bytes: 100,
        scarcity_weight: 1,
        ..Constraints::default()
    };
    let p = disjoint_paths(&g, n(1), n(4), Disjointness::Vertex, &c, 1).unwrap();
    assert_eq!(p[0].nodes, vec![n(1), n(3), n(4)]);
    // Without a scarcity weight the tie is broken by node order, so route 2 can win.
    let p = disjoint_paths(
        &g,
        n(1),
        n(4),
        Disjointness::Vertex,
        &Constraints {
            msg_bytes: 100,
            ..Constraints::default()
        },
        1,
    )
    .unwrap();
    assert_eq!(p[0].nodes, vec![n(1), n(2), n(4)]);
}

// ---- cross-checks against brute force ---------------------------------------------------------

fn reachable(adj: &[Vec<usize>], s: usize, t: usize, removed: &BTreeSet<usize>) -> bool {
    let mut seen = vec![false; adj.len()];
    let mut stack = vec![s];
    seen[s] = true;
    while let Some(u) = stack.pop() {
        if u == t {
            return true;
        }
        for &v in &adj[u] {
            if !seen[v] && !removed.contains(&v) {
                seen[v] = true;
                stack.push(v);
            }
        }
    }
    false
}

#[test]
fn vertex_disjoint_count_equals_the_minimum_vertex_cut_menger() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..150 {
        let size = 7usize; // s = 0, t = 6, middle 1..=5, no direct s-t link
        let mut adj = vec![Vec::new(); size];
        let mut g = Graph::new();
        for i in 0..size as u32 {
            g.add_node(n(i), d(i));
        }
        for a in 0..size {
            for b in a + 1..size {
                if (a, b) != (0, 6) && rng.chance(40) {
                    adj[a].push(b);
                    adj[b].push(a);
                    g.add_link(
                        n(a as u32),
                        n(b as u32),
                        1 + (rng.next() % 9) as u32,
                        1000,
                        1000,
                    );
                }
            }
        }
        let mut best = usize::MAX;
        for mask in 0u32..32 {
            let removed: BTreeSet<usize> = (0..5)
                .filter(|i| mask >> i & 1 == 1)
                .map(|i| i + 1)
                .collect();
            if !reachable(&adj, 0, 6, &removed) {
                best = best.min(removed.len());
            }
        }
        let c = Constraints::default();
        assert_eq!(
            count(&g, 0, 6, Disjointness::Vertex, &c),
            best,
            "adj {adj:?}"
        );
        // Each node is its own domain here, so domain-disjoint equals vertex-disjoint, and
        // edge-disjoint can only be at least as many.
        assert_eq!(count(&g, 0, 6, Disjointness::Domain, &c), best);
        assert!(count(&g, 0, 6, Disjointness::Edge, &c) >= best);
        // Every path found is a real path with consistent latency.
        for p in disjoint_paths(&g, n(0), n(6), Disjointness::Vertex, &c, usize::MAX).unwrap() {
            assert!(p.hops().all(|(a, b)| g.link(a, b).is_some()));
            assert_eq!(
                p.latency_ms,
                p.hops()
                    .map(|(a, b)| u64::from(g.link(a, b).unwrap().latency_ms))
                    .sum::<u64>()
            );
        }
    }
}

#[test]
fn domain_disjoint_count_equals_the_minimum_domain_cut_when_domains_are_cliques() {
    let mut rng = Rng(0x0fed_cba9_8765_4321);
    for _ in 0..120 {
        // s = 100 (domain 100), t = 101 (domain 101), middle nodes 1..=6 in domains 0..=3.
        let mut g = Graph::new();
        g.add_node(n(100), d(100));
        g.add_node(n(101), d(101));
        let dom: Vec<u32> = (1..=6).map(|_| (rng.next() % 4) as u32).collect();
        for (i, &dm) in dom.iter().enumerate() {
            g.add_node(n(i as u32 + 1), d(dm));
        }
        let ids: Vec<u32> = std::iter::once(100)
            .chain(std::iter::once(101))
            .chain(1..=6)
            .collect();
        for (x, &a) in ids.iter().enumerate() {
            for &b in &ids[x + 1..] {
                if (a, b) == (100, 101) {
                    continue;
                }
                let same_domain = g.domain(n(a)) == g.domain(n(b));
                if same_domain || rng.chance(35) {
                    g.add_link(n(a), n(b), 1 + (rng.next() % 5) as u32, 1000, 1000);
                }
            }
        }
        // Brute force: fewest middle domains whose removal disconnects s from t.
        let idx = |id: u32| ids.iter().position(|&x| x == id).unwrap();
        let mut adj = vec![Vec::new(); ids.len()];
        for (&a, m) in &g.links {
            for &b in m.keys() {
                adj[idx(a.0)].push(idx(b.0));
            }
        }
        let doms: Vec<u32> = (0..4).collect();
        let mut best = usize::MAX;
        for mask in 0u32..16 {
            let cut: Vec<u32> = doms
                .iter()
                .copied()
                .filter(|x| mask >> x & 1 == 1)
                .collect();
            let removed: BTreeSet<usize> = ids
                .iter()
                .filter(|&&id| g.domain(n(id)).is_some_and(|dm| cut.contains(&dm.0)))
                .map(|&id| idx(id))
                .collect();
            if !reachable(&adj, idx(100), idx(101), &removed) {
                best = best.min(cut.len());
            }
        }
        let got = count(&g, 100, 101, Disjointness::Domain, &Constraints::default());
        assert_eq!(got, best, "domains {dom:?}");
    }
}

// ---- requirements and plans -------------------------------------------------------------------

fn req(t: usize, f: usize, tampering: bool, protection: Protection) -> Requirement {
    Requirement {
        corrupt_domains: t,
        path_failures: f,
        tampering,
        protection,
    }
}

#[test]
fn sharing_parameters_follow_the_stated_arithmetic() {
    let sp = |r: Requirement| sharing_parameters(&r).unwrap();
    assert_eq!(
        sp(req(0, 0, false, Protection::None)),
        SharingParameters {
            paths: 1,
            threshold: 1
        }
    );
    assert_eq!(sp(req(0, 2, false, Protection::None)).paths, 3);
    assert_eq!(
        sp(req(2, 1, false, Protection::None)),
        SharingParameters {
            paths: 4,
            threshold: 3
        }
    );
    // Authenticated shares: 2t + 1 paths for t tampering domains.
    for t in 1..6 {
        assert_eq!(
            sp(req(t, 0, true, Protection::Authenticated)).paths,
            2 * t + 1
        );
        assert_eq!(
            sp(req(t, 0, true, Protection::ReedSolomon)).paths,
            3 * t + 1
        );
        assert_eq!(
            sp(req(t, 3, true, Protection::Authenticated)).paths,
            2 * t + 1 + 3
        );
    }
    assert_eq!(
        sharing_parameters(&req(1, 0, true, Protection::None)),
        Err(RoutingError::UnprotectedTampering)
    );
    // Not needed without tampering, so no error there.
    assert!(sharing_parameters(&req(1, 0, false, Protection::Authenticated)).is_ok());
}

/// Source 1 and destination 2 with `relays` single-node domains between them.
fn star(relays: u32) -> Graph {
    let mut nodes = vec![(1, 1), (2, 2)];
    let mut links = Vec::new();
    for i in 0..relays {
        let r = 10 + i;
        nodes.push((r, 10 + i));
        links.push((1, r, 5 + i));
        links.push((r, 2, 5 + i));
    }
    build(&nodes, &links)
}

#[test]
fn a_plan_keeps_at_least_k_paths_clear_of_any_t_corrupt_domains() {
    let g = star(6);
    let r = req(2, 0, true, Protection::Authenticated); // needs 5 domain-disjoint paths
    let plan = plan_transmission(
        &g,
        n(1),
        n(2),
        &r,
        &Constraints::default(),
        Disjointness::Domain,
    )
    .unwrap();
    assert_eq!(plan.paths.len(), 5);
    assert_eq!(
        plan.params,
        SharingParameters {
            paths: 5,
            threshold: 3
        }
    );
    // The five cheapest relays were chosen.
    let used: BTreeSet<DomainId> = plan.paths.iter().flat_map(|p| p.domains(&g)).collect();
    assert_eq!(used.len(), 5 + 2);
    assert!(!used.contains(&d(15)));
    // For every choice of t = 2 corrupt relay domains, the untouched paths still reach k.
    let relays: Vec<DomainId> = (10..16).map(d).collect();
    for i in 0..relays.len() {
        for j in i..relays.len() {
            let bad: BTreeSet<DomainId> = [relays[i], relays[j]].into_iter().collect();
            let touched = plan
                .paths
                .iter()
                .filter(|p| !p.domains(&g).is_disjoint(&bad))
                .count();
            assert!(touched <= bad.len());
            assert!(plan.paths.len() - touched >= plan.params.threshold);
        }
    }
    // One path short: an explicit error saying how many exist.
    let short = star(4);
    assert_eq!(
        plan_transmission(
            &short,
            n(1),
            n(2),
            &r,
            &Constraints::default(),
            Disjointness::Domain
        )
        .unwrap_err(),
        RoutingError::Insufficient {
            found: 4,
            needed: 5
        }
    );
}

#[test]
fn the_router_replaces_failed_paths_and_refuses_what_cannot_be_replaced() {
    let g = star(6);
    let r = req(2, 0, true, Protection::Authenticated);
    let mut router = Router::new(
        g,
        n(1),
        n(2),
        r,
        Constraints::default(),
        Disjointness::Domain,
    )
    .unwrap();
    assert!(router.broken().is_empty());
    let before = router.plan().clone();
    // A link of the plan fails: that path is broken and one new path replaces it.
    router.fail_link(n(10), n(2));
    assert_eq!(router.broken().len(), 1);
    assert_eq!(
        router.replan().unwrap(),
        Replan {
            kept: 4,
            replaced: 1
        }
    );
    assert!(router.broken().is_empty());
    assert!(
        router
            .plan()
            .paths
            .iter()
            .all(|p| !p.nodes.contains(&n(10)))
    );
    // The adversary takes over a whole domain: nothing in it is used any more.
    router.exclude_domain(d(11));
    assert_eq!(router.broken().len(), 1);
    // Only 4 usable relays remain (10 and 11 are gone, 12..15 left): one short, so the re-plan
    // fails and the old plan is kept unchanged.
    let kept = router.plan().clone();
    assert_eq!(
        router.replan().unwrap_err(),
        RoutingError::Insufficient {
            found: 4,
            needed: 5
        }
    );
    assert_eq!(router.plan(), &kept);
    assert_ne!(&before, &kept);
    // A node failure of a different relay changes nothing further about the error.
    router.fail_node(n(12));
    assert!(matches!(
        router.replan(),
        Err(RoutingError::Insufficient {
            found: 3,
            needed: 5
        })
    ));
}

#[test]
fn allocation_spends_budgets_atomically_and_replenishment_restores_them() {
    let mut g = star(3);
    g.set_replenish(n(1), n(10), 40, 0);
    g.links
        .get_mut(&n(1))
        .unwrap()
        .get_mut(&n(10))
        .unwrap()
        .secret_bytes = 100;
    let r = req(1, 0, true, Protection::Authenticated); // 3 paths
    let mut router = Router::new(
        g,
        n(1),
        n(2),
        r,
        Constraints::default(),
        Disjointness::Domain,
    )
    .unwrap();
    let a = router.allocate(60).unwrap();
    assert_eq!(a.per_link[&(n(1), n(10))], 60);
    assert_eq!(router.graph().link(n(1), n(10)).unwrap().secret_bytes, 40);
    assert_eq!(router.graph().link(n(10), n(2)).unwrap().secret_bytes, 940);
    // Not enough on one link: nothing at all is spent, including on the links that had enough.
    let snapshot: Vec<u64> = [(1, 11), (11, 2), (1, 10), (10, 2)]
        .iter()
        .map(|&(x, y)| router.graph().link(n(x), n(y)).unwrap().secret_bytes)
        .collect();
    match router.allocate(60) {
        Err(RoutingError::Exhausted {
            from,
            to,
            have: 40,
            need: 60,
        }) => assert_eq!((from, to), (n(1), n(10))),
        other => panic!("{other:?}"),
    }
    let after: Vec<u64> = [(1, 11), (11, 2), (1, 10), (10, 2)]
        .iter()
        .map(|&(x, y)| router.graph().link(n(x), n(y)).unwrap().secret_bytes)
        .collect();
    assert_eq!(snapshot, after);
    // One provisioning tick brings the link to 80, enough again.
    router.replenish();
    assert_eq!(router.graph().link(n(1), n(10)).unwrap().secret_bytes, 80);
    router.allocate(60).unwrap();
}

// ---- the flow bound ---------------------------------------------------------------------------

#[test]
fn wire_secret_flow_equals_the_minimum_cut_of_the_budgets() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for _ in 0..150 {
        let size = 7usize;
        let mut g = Graph::new();
        for i in 0..size as u32 {
            g.add_node(n(i), d(i));
        }
        let mut cap = vec![vec![0u64; size]; size];
        for a in 0..size {
            for b in 0..size {
                if a != b && rng.chance(35) {
                    cap[a][b] = 1 + rng.next() % 50;
                }
            }
        }
        for a in 0..size {
            for b in a + 1..size {
                if cap[a][b] > 0 || cap[b][a] > 0 {
                    g.add_link(n(a as u32), n(b as u32), 1, cap[a][b], cap[b][a]);
                }
            }
        }
        // Brute-force min cut over sets S containing s (0) and not t (6).
        let mut best = u64::MAX;
        for mask in 0u32..(1 << (size - 2)) {
            let s_side: BTreeSet<usize> = std::iter::once(0)
                .chain((1..size - 1).filter(|i| mask >> (i - 1) & 1 == 1))
                .collect();
            let cut: u64 = s_side
                .iter()
                .flat_map(|&a| {
                    (0..size)
                        .filter(|b| !s_side.contains(b))
                        .map(move |b| (a, b))
                })
                .map(|(a, b)| cap[a][b])
                .sum();
            best = best.min(cut);
        }
        assert_eq!(
            wire_secret_flow(&g, n(0), n(6), &Constraints::default()).unwrap(),
            best
        );
    }
    // Exclusions and failures reduce it; endpoint errors are reported.
    let g = star(3);
    let full = wire_secret_flow(&g, n(1), n(2), &Constraints::default()).unwrap();
    assert_eq!(full, 3000);
    let mut c = Constraints::default();
    c.exclude_domains.insert(d(10));
    c.fail_link(n(11), n(2));
    assert_eq!(wire_secret_flow(&g, n(1), n(2), &c).unwrap(), 1000);
    assert_eq!(
        wire_secret_flow(&g, n(1), n(1), &Constraints::default()),
        Err(RoutingError::SameEndpoints)
    );
    assert_eq!(
        wire_secret_flow(&g, n(1), n(99), &Constraints::default()),
        Err(RoutingError::UnknownNode(n(99)))
    );
}

#[test]
fn graph_construction_rules() {
    let mut g = Graph::new();
    g.add_node(n(1), d(1));
    g.add_node(n(2), d(2));
    assert!(!g.add_link(n(1), n(1), 1, 1, 1), "no self links");
    assert!(!g.add_link(n(1), n(9), 1, 1, 1), "unknown endpoint");
    assert!(g.add_link(n(1), n(2), 0, 5, 7));
    assert_eq!(
        g.link(n(1), n(2)).unwrap().latency_ms,
        1,
        "latency is at least 1"
    );
    assert_eq!(
        (
            g.link(n(1), n(2)).unwrap().secret_bytes,
            g.link(n(2), n(1)).unwrap().secret_bytes
        ),
        (5, 7)
    );
    assert_eq!(g.domain(n(2)), Some(d(2)));
    assert_eq!(g.nodes().count(), 2);
}

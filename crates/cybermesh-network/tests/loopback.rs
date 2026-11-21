//! Real libp2p nodes on 127.0.0.1: delivery, allowlist enforcement and rate limiting.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use cybermesh_network::{
    Acceptance, Multiaddr, NetConfig, NetEvent, NetworkHandle, keypair_from_seed, spawn,
};
use libp2p::PeerId;
use libp2p::multiaddr::Protocol;

const TOPIC: &str = "/cybermesh/test/v1/tasks";

fn key(i: u8) -> libp2p::identity::Keypair {
    keypair_from_seed(&[i; 32]).unwrap()
}

fn listen() -> Vec<Multiaddr> {
    vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()]
}

async fn listening_addr(h: &NetworkHandle) -> Multiaddr {
    loop {
        if let Some(NetEvent::Listening(a)) = h.next_event().await {
            return a.with(Protocol::P2p(h.local_peer_id));
        }
    }
}

fn cfg(allowed: Vec<PeerId>, bootstrap: Vec<Multiaddr>) -> NetConfig {
    NetConfig {
        listen: listen(),
        bootstrap,
        allowed_peers: allowed,
        subscribe: vec![TOPIC.into()],
        heartbeat: Duration::from_millis(100),
        redial_interval: Duration::from_millis(200),
        ..NetConfig::default()
    }
}

async fn publish_until_ok(h: &NetworkHandle, data: Vec<u8>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while h.publish(TOPIC, data.clone()).await.is_err() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no subscribed peers in time"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn next_message(
    h: &NetworkHandle,
    within: Duration,
) -> Option<cybermesh_network::InboundMessage> {
    tokio::time::timeout(within, async {
        loop {
            match h.next_event().await {
                Some(NetEvent::Message(m)) => return m,
                Some(_) => {}
                None => panic!("network stopped"),
            }
        }
    })
    .await
    .ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowlisted_peers_exchange_messages() {
    let (ka, kb) = (key(1), key(2));
    let (pa, pb) = (ka.public().to_peer_id(), kb.public().to_peer_id());
    let a = spawn(ka, cfg(vec![pb], vec![])).unwrap();
    let addr_a = listening_addr(&a).await;
    let b = spawn(kb, cfg(vec![pa], vec![addr_a])).unwrap();

    publish_until_ok(&a, b"hello from a".to_vec()).await;
    let m = next_message(&b, Duration::from_secs(10))
        .await
        .expect("delivery");
    assert_eq!(m.data, b"hello from a");
    assert_eq!(m.author, Some(pa));
    b.report(&m, Acceptance::Accept).await;
    assert!(a.stats.snapshot().bytes_out >= 12);
    assert!(b.stats.snapshot().messages_in >= 1);
}

/// A bootstrap address may name the peer by host name (`/dns4/...`); `localhost` resolves
/// through the hosts file, so this needs no network access.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peers_connect_through_a_dns_address() {
    let (ka, kb) = (key(5), key(6));
    let (pa, pb) = (ka.public().to_peer_id(), kb.public().to_peer_id());
    let a = spawn(ka, cfg(vec![pb], vec![])).unwrap();
    let ip = listening_addr(&a).await;
    let port = ip
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .unwrap();
    let dns: Multiaddr = format!("/dns4/localhost/tcp/{port}/p2p/{pa}")
        .parse()
        .unwrap();
    let b = spawn(kb, cfg(vec![pa], vec![dns])).unwrap();

    publish_until_ok(&a, b"hello by name".to_vec()).await;
    let m = next_message(&b, Duration::from_secs(10))
        .await
        .expect("delivery over a /dns4 address");
    assert_eq!(m.data, b"hello by name");
    assert_eq!(m.author, Some(pa));
}

/// A host name that resolves to a peer with a different identity is refused by the Noise
/// handshake: DNS can only make a dial fail, never substitute a peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_address_cannot_substitute_another_peer() {
    let (ka, kb, kc) = (key(7), key(8), key(9));
    let (pa, pb, pc) = (
        ka.public().to_peer_id(),
        kb.public().to_peer_id(),
        kc.public().to_peer_id(),
    );
    // C listens; B is told that `localhost:<C's port>` is A.
    let c = spawn(kc, cfg(vec![pb], vec![])).unwrap();
    let ip = listening_addr(&c).await;
    let port = ip
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .unwrap();
    let wrong: Multiaddr = format!("/dns4/localhost/tcp/{port}/p2p/{pa}")
        .parse()
        .unwrap();
    // B would accept C as a peer: only the peer id pinned in the address keeps it out.
    let b = spawn(kb, cfg(vec![pa, pc], vec![wrong])).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    // B never connects to C under A's name, so C's message never reaches B.
    let _ = c.publish(TOPIC, b"impostor".to_vec()).await;
    assert!(next_message(&b, Duration::from_secs(2)).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unenrolled_peer_cannot_connect_or_inject() {
    let (ka, kc) = (key(3), key(9));
    let pc = kc.public().to_peer_id();
    // A allows nobody; C allows A and dials it.
    let a = spawn(ka.clone(), cfg(vec![], vec![])).unwrap();
    let addr_a = listening_addr(&a).await;
    let c = spawn(kc, cfg(vec![ka.public().to_peer_id()], vec![addr_a])).unwrap();
    // C never gets a usable connection, so publishing keeps failing and A sees nothing.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let _ = c.publish(TOPIC, b"injected".to_vec()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match a.next_event().await {
                Some(NetEvent::Message(m)) => return Some(m),
                Some(NetEvent::PeerConnected(p)) if p == pc => return None,
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await;
    assert!(
        !matches!(got, Ok(Some(_))),
        "message from unenrolled peer delivered"
    );
    assert!(
        !matches!(got, Ok(None)),
        "unenrolled peer connection was accepted"
    );
    assert_eq!(a.stats.snapshot().messages_in, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_peer_rate_limit_drops_floods() {
    let (ka, kb) = (key(4), key(5));
    let (pa, pb) = (ka.public().to_peer_id(), kb.public().to_peer_id());
    let mut ca = cfg(vec![pb], vec![]);
    ca.per_peer_burst = 5;
    ca.per_peer_refill_per_sec = 1;
    let a = spawn(ka, ca).unwrap();
    let addr_a = listening_addr(&a).await;
    let b = spawn(kb, cfg(vec![pa], vec![addr_a])).unwrap();
    publish_until_ok(&b, b"warmup".to_vec()).await;
    for i in 0..60u32 {
        let _ = b.publish(TOPIC, format!("flood-{i}").into_bytes()).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let s = a.stats.snapshot();
    assert!(s.dropped_rate_limited > 0, "{s:?}");
    assert!(s.messages_in - s.dropped_rate_limited <= 8, "{s:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnects_after_peer_restart() {
    let (ka, kb) = (key(6), key(7));
    let (pa, pb) = (ka.public().to_peer_id(), kb.public().to_peer_id());
    // Fixed port so the restarted node is reachable at the same bootstrap address.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{pa}")
        .parse()
        .unwrap();
    let mk_a = || {
        let mut c = cfg(vec![pb], vec![]);
        c.listen = vec![format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()];
        spawn(ka.clone(), c).unwrap()
    };
    let a = mk_a();
    let b = spawn(kb, cfg(vec![pa], vec![addr])).unwrap();
    publish_until_ok(&b, b"before".to_vec()).await;
    assert!(next_message(&a, Duration::from_secs(10)).await.is_some());
    a.shutdown().await;
    drop(a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let a2 = mk_a();
    // B redials the bootstrap address and delivery resumes.
    publish_until_ok(&b, b"after".to_vec()).await;
    let m = next_message(&a2, Duration::from_secs(15))
        .await
        .expect("delivery after restart");
    assert_eq!(m.data, b"after");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_peer_is_disconnected_and_ignored() {
    let (ka, kb) = (key(11), key(12));
    let (pa, pb) = (ka.public().to_peer_id(), kb.public().to_peer_id());
    let a = spawn(ka, cfg(vec![pb], vec![])).unwrap();
    let addr_a = listening_addr(&a).await;
    let b = spawn(kb, cfg(vec![pa], vec![addr_a])).unwrap();
    publish_until_ok(&b, b"before revocation".to_vec()).await;
    assert!(next_message(&a, Duration::from_secs(10)).await.is_some());
    // A loads a manifest in which B is revoked.
    a.set_allowed(vec![]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    for _ in 0..10 {
        let _ = b.publish(TOPIC, b"after revocation".to_vec()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = next_message(&a, Duration::from_secs(2)).await;
    assert!(got.is_none(), "message from a revoked peer was delivered");
}

/// Delivers messages from `from` to `to` until one arrives, reporting it with `verdict`.
async fn deliver(
    from: &NetworkHandle,
    to: &NetworkHandle,
    data: &[u8],
    verdict: Acceptance,
) -> bool {
    publish_until_ok(from, data.to_vec()).await;
    match next_message(to, Duration::from_secs(5)).await {
        Some(m) => {
            assert_eq!(m.data, data);
            to.report(&m, verdict).await;
            true
        }
        None => false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_sending_invalid_messages_is_graylisted() {
    use cybermesh_network::{GOSSIP_THRESHOLD, GRAYLIST_THRESHOLD, SCORE_GRAYLISTED};
    let (ka, km) = (key(31), key(32));
    let (pa, pm) = (ka.public().to_peer_id(), km.public().to_peer_id());
    let a = spawn(ka, cfg(vec![pm], vec![])).unwrap();
    let addr_a = listening_addr(&a).await;
    let m = spawn(km, cfg(vec![pa], vec![addr_a])).unwrap();
    assert!(deliver(&m, &a, b"valid 0", Acceptance::Accept).await);
    assert_eq!(a.peer_score(pm).await, Some(0.0));
    // One invalid message is tolerated: one false positive costs an honest peer nothing.
    assert!(deliver(&m, &a, b"forged 1", Acceptance::Reject).await);
    assert_eq!(a.author_score(pm).await, 0.0);
    assert_eq!(a.peer_score(pm).await, Some(0.0));
    // A second: no more gossip with it (and out of the mesh), but still heard.
    assert!(deliver(&m, &a, b"forged 2", Acceptance::Reject).await);
    let s = a.peer_score(pm).await.unwrap();
    assert!(s < GOSSIP_THRESHOLD && s > GRAYLIST_THRESHOLD, "{s}");
    // A third: graylisted. Everything it sends is now ignored, valid messages included.
    assert!(deliver(&m, &a, b"forged 3", Acceptance::Reject).await);
    assert_eq!(a.author_score(pm).await, SCORE_GRAYLISTED);
    assert!(a.peer_score(pm).await.unwrap() < GRAYLIST_THRESHOLD);
    for i in 0..10 {
        let _ = m
            .publish(TOPIC, format!("valid after {i}").into_bytes())
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        next_message(&a, Duration::from_secs(2)).await.is_none(),
        "a graylisted peer was heard"
    );
    assert_eq!(a.stats.snapshot().rejected_by_application, 3);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(a.stats.snapshot().penalised_peers, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignored_messages_never_cost_a_peer_anything() {
    let (ka, kb) = (key(33), key(34));
    let (pa, pb) = (ka.public().to_peer_id(), kb.public().to_peer_id());
    let a = spawn(ka, cfg(vec![pb], vec![])).unwrap();
    let addr_a = listening_addr(&a).await;
    let b = spawn(kb, cfg(vec![pa], vec![addr_a])).unwrap();
    // Expired, from a newer manifest, over a quota: dropped, never held against the peer.
    for i in 0..20 {
        assert!(deliver(&b, &a, format!("stale {i}").as_bytes(), Acceptance::Ignore).await);
    }
    assert_eq!(a.peer_score(pb).await, Some(0.0));
    assert!(deliver(&b, &a, b"still heard", Acceptance::Accept).await);
}

#[test]
fn scoring_costs_only_invalid_messages_and_forgets_them_slowly() {
    use cybermesh_network::author_score;
    let topics = vec![TOPIC.to_owned()];
    let (p, t) = cybermesh_network::peer_scoring(&topics);
    assert!(p.validate().is_ok() && t.validate().is_ok());
    let tp = &p.topics[&libp2p::gossipsub::IdentTopic::new(TOPIC).hash()];
    // Nothing to earn, no penalty other than invalid messages (and protocol misbehaviour).
    assert_eq!(tp.time_in_mesh_weight, 0.0);
    assert_eq!(tp.first_message_deliveries_weight, 0.0);
    assert_eq!(tp.mesh_message_deliveries_weight, 0.0);
    assert_eq!(tp.mesh_failure_penalty_weight, 0.0);
    assert_eq!(p.ip_colocation_factor_weight, 0.0);
    assert_eq!(p.slow_peer_weight, 0.0);
    // Authors' penalties are applied as the application score, at face value.
    assert_eq!(p.app_specific_weight, 1.0);
    assert_eq!(author_score(1.0), 0.0, "one invalid message is tolerated");
    let warned = author_score(2.0);
    assert!(warned < t.gossip_threshold && warned >= t.publish_threshold);
    assert!(author_score(3.0) < t.graylist_threshold);
    // The count halves every ten minutes: a second message within ten minutes warns, a
    // third (about) graylists, and an older one has faded.
    assert_eq!(author_score(0.5 + 1.0), warned);
    assert!(author_score(1.0 + 0.5 + 1.0) < t.graylist_threshold);
    assert_eq!(author_score(0.49 + 1.0), 0.0);
    // Gossipsub's own invalid messages decay at the same rate; scores outlive reconnection.
    let steps =
        cybermesh_network::INVALID_MESSAGE_HALF_LIFE.as_secs_f64() / p.decay_interval.as_secs_f64();
    assert!((tp.invalid_message_deliveries_decay.powf(steps) - 0.5).abs() < 1e-9);
    assert!(p.retain_score >= Duration::from_secs(3600));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_messages_count_against_their_author_not_the_relay() {
    // M reaches A only through R. R forwards what it accepts; A finds M's messages invalid.
    let (ka, kr, km) = (key(35), key(36), key(37));
    let (pa, pr, pm) = (
        ka.public().to_peer_id(),
        kr.public().to_peer_id(),
        km.public().to_peer_id(),
    );
    let r = spawn(kr, cfg(vec![pa, pm], vec![])).unwrap();
    let addr_r = listening_addr(&r).await;
    let a = spawn(ka, cfg(vec![pr, pm], vec![addr_r.clone()])).unwrap();
    let m = spawn(km, cfg(vec![pr, pa], vec![addr_r])).unwrap();
    // R accepts (and so forwards) everything it receives.
    let relay = tokio::spawn(async move {
        loop {
            match r.next_event().await {
                Some(NetEvent::Message(msg)) => r.report(&msg, Acceptance::Accept).await,
                Some(_) => {}
                None => break,
            }
        }
    });
    let mut rejected = 0;
    for i in 0..30 {
        let _ = m.publish(TOPIC, format!("forged {i}").into_bytes()).await;
        if let Some(msg) = next_message(&a, Duration::from_millis(500)).await {
            assert_eq!(msg.author, Some(pm));
            assert_eq!(msg.propagation_source, pr, "M is not connected to A");
            a.report(&msg, Acceptance::Reject).await;
            rejected += 1;
            if rejected == 3 {
                break;
            }
        }
    }
    assert_eq!(rejected, 3, "M's messages did not reach A through R");
    // The relay is not charged; the author is graylisted although it is not connected ...
    assert_eq!(a.peer_score(pr).await, Some(0.0), "the relay was charged");
    assert_eq!(a.author_score(pr).await, 0.0);
    assert_eq!(
        a.author_score(pm).await,
        cybermesh_network::SCORE_GRAYLISTED
    );
    // ... so its messages are dropped although they arrive through an accepting relay.
    for i in 0..10 {
        let _ = m.publish(TOPIC, format!("valid {i}").into_bytes()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(next_message(&a, Duration::from_secs(2)).await.is_none());
    assert!(a.stats.snapshot().dropped_penalised >= 1);
    relay.abort();
}

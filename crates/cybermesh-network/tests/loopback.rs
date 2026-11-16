//! Real libp2p nodes on 127.0.0.1: delivery, allowlist enforcement and rate limiting.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use cybermesh_network::{Acceptance, Multiaddr, NetConfig, NetEvent, NetworkHandle, keypair_from_seed, spawn};
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
        assert!(tokio::time::Instant::now() < deadline, "no subscribed peers in time");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn next_message(h: &NetworkHandle, within: Duration) -> Option<cybermesh_network::InboundMessage> {
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
    let m = next_message(&b, Duration::from_secs(10)).await.expect("delivery");
    assert_eq!(m.data, b"hello from a");
    assert_eq!(m.author, Some(pa));
    b.report(&m, Acceptance::Accept).await;
    assert!(a.stats.snapshot().bytes_out >= 12);
    assert!(b.stats.snapshot().messages_in >= 1);
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
    assert!(!matches!(got, Ok(Some(_))), "message from unenrolled peer delivered");
    assert!(!matches!(got, Ok(None)), "unenrolled peer connection was accepted");
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
    let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{pa}").parse().unwrap();
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
    let m = next_message(&a2, Duration::from_secs(15)).await.expect("delivery after restart");
    assert_eq!(m.data, b"after");
}

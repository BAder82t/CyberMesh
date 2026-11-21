use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cybermesh_protocol::ratelimit::RateLimiter;
use libp2p::futures::StreamExt as _;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance, MessageId};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    Multiaddr, PeerId, Swarm, allow_block_list, connection_limits, identity, noise, tcp, yamux,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::stats::NetStats;

/// Score cost of each invalid message that gossipsub detects itself (a broken message
/// signature), squared in the count (gossipsub P4).
pub const INVALID_MESSAGE_WEIGHT: f64 = -10.0;
/// The count of an author's invalid messages halves this often.
pub const INVALID_MESSAGE_HALF_LIFE: Duration = Duration::from_secs(600);
/// Below this score a peer is no longer gossiped with or kept in the mesh.
pub const GOSSIP_THRESHOLD: f64 = -10.0;
/// Below this score nothing is published to a peer.
pub const PUBLISH_THRESHOLD: f64 = -50.0;
/// Below this score everything a peer sends is ignored.
pub const GRAYLIST_THRESHOLD: f64 = -80.0;
/// An author's score after about two recent invalid messages: below the gossip threshold,
/// above the publish threshold.
pub const SCORE_WARNED: f64 = -40.0;
/// An author's score after about three recent invalid messages: graylisted.
pub const SCORE_GRAYLISTED: f64 = -100.0;

/// The score of an author with `count` recent invalid messages (a count that halves every
/// [`INVALID_MESSAGE_HALF_LIFE`]): a single one is tolerated, so one false positive costs an
/// honest node nothing.
#[must_use]
pub fn author_score(count: f64) -> f64 {
    if count >= 2.5 {
        SCORE_GRAYLISTED
    } else if count >= 1.5 {
        SCORE_WARNED
    } else {
        0.0
    }
}

/// `c` decayed from `at` to `now`.
fn decayed(c: f64, at: Instant, now: Instant) -> f64 {
    c * 0.5f64.powf(
        now.saturating_duration_since(at).as_secs_f64() / INVALID_MESSAGE_HALF_LIFE.as_secs_f64(),
    )
}

/// Recent invalid messages per author, decaying. Only enrolled authors reach it, so it is
/// bounded by the allowlist.
#[derive(Debug, Default)]
struct Penalties {
    counts: HashMap<PeerId, (f64, Instant)>,
}

impl Penalties {
    fn score(&self, p: &PeerId, now: Instant) -> f64 {
        author_score(
            self.counts
                .get(p)
                .map_or(0.0, |(c, at)| decayed(*c, *at, now)),
        )
    }

    /// Counts one more invalid message by `p`; returns its new score.
    fn add(&mut self, p: PeerId, now: Instant) -> f64 {
        let c = self
            .counts
            .get(&p)
            .map_or(0.0, |(c, at)| decayed(*c, *at, now))
            + 1.0;
        self.counts.insert(p, (c, now));
        author_score(c)
    }

    /// Every tracked author's current score; authors whose count has decayed away are
    /// forgotten (their last score, 0, is still returned once).
    fn refresh(&mut self, now: Instant) -> Vec<(PeerId, f64)> {
        let mut out = Vec::with_capacity(self.counts.len());
        self.counts.retain(|p, (c, at)| {
            *c = decayed(*c, *at, now);
            *at = now;
            out.push((*p, author_score(*c)));
            *c >= 0.05
        });
        out
    }
}

/// Peer scoring for a permissioned network: only provable misbehaviour costs a peer, and
/// nothing can be earned.
///
/// - **Invalid messages.** A message the application `Reject`s counts against its
///   **author**, whatever peer delivered it. Relays are never charged: they forward only
///   what their own checks accepted, and may lack the context that makes a message invalid
///   elsewhere. The count halves every [`INVALID_MESSAGE_HALF_LIFE`] and sets the author's
///   score ([`author_score`], applied as gossipsub's application-specific score):
///   - one invalid message is tolerated;
///   - about two in ten minutes take the author out of the mesh and stop gossip with it;
///   - about three graylist it: gossipsub ignores what it sends (including what it relays
///     for others), and this node drops every message it authored, also when another peer
///     relays it.
///
///   `Acceptance::Ignore` (clocks, a lagging manifest, version skew, quotas) never costs
///   anything.
/// - **Gossipsub's own checks.** A message with a broken gossipsub signature costs the peer
///   that delivered it [`INVALID_MESSAGE_WEIGHT`] times the square of the count; protocol
///   misbehaviour (re-grafting during backoff, broken gossip promises) costs as in gossipsub,
///   beyond a tolerance of 6.
/// - **Not used:** rewards for time in the mesh or first deliveries (a long-connected
///   attacker could bank them against penalties), penalties for under-delivery (low-traffic
///   topics such as `checkpoints` would punish honest peers), for many peers behind one IP
///   address (organisations behind NAT; peers are enrolled anyway) and for slow peers.
///
/// Gossipsub scores survive a reconnection for an hour, and author counts are kept by this
/// node regardless of connections, so reconnecting resets nothing.
#[must_use]
pub fn peer_scoring(
    topics: &[String],
) -> (gossipsub::PeerScoreParams, gossipsub::PeerScoreThresholds) {
    let interval = Duration::from_secs(1);
    let decay = 0.5f64.powf(interval.as_secs_f64() / INVALID_MESSAGE_HALF_LIFE.as_secs_f64());
    let topic = gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.0,
        first_message_deliveries_weight: 0.0,
        mesh_message_deliveries_weight: 0.0,
        mesh_failure_penalty_weight: 0.0,
        invalid_message_deliveries_weight: INVALID_MESSAGE_WEIGHT,
        invalid_message_deliveries_decay: decay,
        ..gossipsub::TopicScoreParams::default()
    };
    let params = gossipsub::PeerScoreParams {
        topics: topics
            .iter()
            .map(|t| (IdentTopic::new(t.clone()).hash(), topic.clone()))
            .collect(),
        app_specific_weight: 1.0,
        ip_colocation_factor_weight: 0.0,
        behaviour_penalty_threshold: 6.0,
        slow_peer_weight: 0.0,
        decay_interval: interval,
        retain_score: Duration::from_secs(3600),
        ..gossipsub::PeerScoreParams::default()
    };
    let thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: GOSSIP_THRESHOLD,
        publish_threshold: PUBLISH_THRESHOLD,
        graylist_threshold: GRAYLIST_THRESHOLD,
        ..gossipsub::PeerScoreThresholds::default()
    };
    (params, thresholds)
}

/// Network configuration.
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub listen: Vec<Multiaddr>,
    /// Bootstrap addresses including `/p2p/<peer id>`; redialled when disconnected.
    pub bootstrap: Vec<Multiaddr>,
    /// Enrolled peers allowed to connect.
    pub allowed_peers: Vec<PeerId>,
    pub subscribe: Vec<String>,
    pub heartbeat: Duration,
    pub max_message_bytes: usize,
    /// Per-peer token bucket: burst size and refill per second (cost = 1 + KiB).
    pub per_peer_burst: u32,
    pub per_peer_refill_per_sec: u32,
    pub inbound_queue: usize,
    pub command_queue: usize,
    /// Outbound application bytes per second (`None` = unlimited).
    pub outbound_bytes_per_sec: Option<u64>,
    pub redial_interval: Duration,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            listen: vec![],
            bootstrap: vec![],
            allowed_peers: vec![],
            subscribe: vec![],
            heartbeat: Duration::from_millis(700),
            max_message_bytes: 256 * 1024,
            per_peer_burst: 50,
            per_peer_refill_per_sec: 10,
            inbound_queue: 256,
            command_queue: 256,
            outbound_bytes_per_sec: None,
            redial_interval: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("transport setup failed: {0}")]
    Setup(String),
    #[error("network task stopped")]
    Stopped,
    #[error("publish failed: {0}")]
    Publish(String),
    /// The same message (author and bytes) was published recently; peers already have it.
    #[error("duplicate message")]
    Duplicate,
}

/// Application verdict on an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Valid: forward to other peers.
    Accept,
    /// Provably invalid (bad signature, forged, malformed, misattributed): drop, and count it
    /// against the peer that sent it ([`peer_scoring`]). Only for what an honest node cannot
    /// produce.
    Reject,
    /// Not useful but not proof of misbehaviour (duplicate, expired, from a manifest this node
    /// does not have yet, another version, over a quota): drop without penalty.
    Ignore,
}

impl From<Acceptance> for MessageAcceptance {
    fn from(a: Acceptance) -> Self {
        match a {
            Acceptance::Accept => MessageAcceptance::Accept,
            Acceptance::Reject => MessageAcceptance::Reject,
            Acceptance::Ignore => MessageAcceptance::Ignore,
        }
    }
}

/// A message awaiting application validation.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub topic: String,
    pub data: Vec<u8>,
    pub propagation_source: PeerId,
    pub author: Option<PeerId>,
    pub message_id: MessageId,
}

/// Events delivered to the application.
#[derive(Debug, Clone)]
pub enum NetEvent {
    Message(InboundMessage),
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    Listening(Multiaddr),
}

enum Command {
    Publish {
        topic: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), NetError>>,
    },
    Report {
        id: MessageId,
        source: PeerId,
        author: Option<PeerId>,
        acceptance: Acceptance,
    },
    SetAllowed(Vec<PeerId>),
    PeerScore {
        peer: PeerId,
        reply: oneshot::Sender<Option<f64>>,
    },
    AuthorScore {
        peer: PeerId,
        reply: oneshot::Sender<f64>,
    },
    Shutdown,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    allowed: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    limits: connection_limits::Behaviour,
    gossipsub: gossipsub::Behaviour,
}

/// Handle to a running network node.
#[derive(Debug)]
pub struct NetworkHandle {
    commands: mpsc::Sender<Command>,
    events: Mutex<mpsc::Receiver<NetEvent>>,
    pub local_peer_id: PeerId,
    pub stats: Arc<NetStats>,
    outbound: Option<Mutex<(f64, Instant)>>,
    outbound_rate: u64,
}

/// Derives the libp2p keypair from a CyberMesh Ed25519 seed. The same key signs CyberMesh
/// envelopes (DSSE, domain-separated) and authenticates the transport (libp2p's own
/// signature prefixes), so signatures cannot be confused across the two protocols.
pub fn keypair_from_seed(seed: &[u8; 32]) -> Result<identity::Keypair, NetError> {
    let mut copy = *seed;
    identity::Keypair::ed25519_from_bytes(&mut copy).map_err(|e| NetError::Setup(e.to_string()))
}

/// Peer id for an enrolled CyberMesh public key.
pub fn peer_id_of(pk: &cybermesh_crypto::PublicKey) -> Result<PeerId, NetError> {
    let ed = identity::ed25519::PublicKey::try_from_bytes(pk.as_bytes())
        .map_err(|e| NetError::Setup(e.to_string()))?;
    Ok(identity::PublicKey::from(ed).to_peer_id())
}

impl NetworkHandle {
    /// Publishes, waiting for the outbound bandwidth budget if one is configured.
    pub async fn publish(&self, topic: &str, data: Vec<u8>) -> Result<(), NetError> {
        if let Some(bucket) = &self.outbound {
            let rate = self.outbound_rate as f64;
            loop {
                let wait = {
                    let mut b = bucket.lock().await;
                    let now = Instant::now();
                    let refill = now.duration_since(b.1).as_secs_f64() * rate;
                    b.0 = (b.0 + refill).min(rate.max(data.len() as f64));
                    b.1 = now;
                    if b.0 >= data.len() as f64 {
                        b.0 -= data.len() as f64;
                        None
                    } else {
                        Some(Duration::from_secs_f64((data.len() as f64 - b.0) / rate))
                    }
                };
                match wait {
                    None => break,
                    Some(d) => tokio::time::sleep(d).await,
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Publish {
                topic: topic.to_owned(),
                data,
                reply: tx,
            })
            .await
            .map_err(|_| NetError::Stopped)?;
        rx.await.map_err(|_| NetError::Stopped)?
    }

    /// Reports the application's validation verdict for an inbound message.
    pub async fn report(&self, msg: &InboundMessage, acceptance: Acceptance) {
        let _ = self
            .commands
            .send(Command::Report {
                id: msg.message_id.clone(),
                source: msg.propagation_source,
                author: msg.author,
                acceptance,
            })
            .await;
    }

    /// Next network event (`None` once the node stopped).
    pub async fn next_event(&self) -> Option<NetEvent> {
        self.events.lock().await.recv().await
    }

    /// Replaces the set of allowed peers (e.g. after a manifest update). Peers that are no
    /// longer allowed are disconnected immediately and their messages rejected.
    pub async fn set_allowed(&self, peers: Vec<PeerId>) {
        let _ = self.commands.send(Command::SetAllowed(peers)).await;
    }

    /// The score of an author of messages: 0 unless it recently sent invalid ones, whether
    /// or not it is connected ([`author_score`]).
    pub async fn author_score(&self, peer: PeerId) -> f64 {
        let (tx, rx) = oneshot::channel();
        if self
            .commands
            .send(Command::AuthorScore { peer, reply: tx })
            .await
            .is_err()
        {
            return 0.0;
        }
        rx.await.unwrap_or(0.0)
    }

    /// A connected peer's gossipsub score (0 for a well-behaved peer; see [`peer_scoring`]).
    pub async fn peer_score(&self, peer: PeerId) -> Option<f64> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::PeerScore { peer, reply: tx })
            .await
            .ok()?;
        rx.await.ok().flatten()
    }

    pub async fn shutdown(&self) {
        let _ = self.commands.send(Command::Shutdown).await;
    }
}

fn peer_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

fn build_swarm(keypair: identity::Keypair, cfg: &NetConfig) -> Result<Swarm<Behaviour>, NetError> {
    let max = cfg.max_message_bytes;
    let heartbeat = cfg.heartbeat;
    let subscribe = cfg.subscribe.clone();
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetError::Setup(e.to_string()))?
        // `/dns4`, `/dns6` and `/dns` peer addresses, resolved with the system resolver
        // configuration. Only addresses in the node's own configuration are dialled (gossip
        // never makes a node dial an address a peer supplied), and every bootstrap address
        // names the peer id that the Noise handshake authenticates, so a spoofed answer can
        // only make a dial fail.
        .with_dns()
        .map_err(|e| NetError::Setup(e.to_string()))?
        .with_behaviour(|key| {
            let gs_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(heartbeat)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .validate_messages()
                // Bind the id to the authenticated author as well as the content, so another
                // peer cannot pre-claim (and get rejected under) an honest message's id.
                .message_id_fn(|m: &gossipsub::Message| {
                    let mut h = Sha256::new();
                    if let Some(src) = &m.source {
                        h.update(src.to_bytes());
                    }
                    h.update([0u8]);
                    h.update(&m.data);
                    MessageId::from(h.finalize().to_vec())
                })
                .max_transmit_size(max)
                .duplicate_cache_time(Duration::from_secs(600))
                .mesh_n_low(2)
                .mesh_n(4)
                .mesh_n_high(8)
                .mesh_outbound_min(1)
                .flood_publish(true)
                .build()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gs_config,
            )
            .map_err(std::io::Error::other)?;
            let (params, thresholds) = peer_scoring(&subscribe);
            gossipsub
                .with_peer_score(params, thresholds)
                .map_err(std::io::Error::other)?;
            let limits = connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_established_per_peer(Some(2))
                    .with_max_established(Some(128))
                    .with_max_pending_incoming(Some(32))
                    .with_max_pending_outgoing(Some(32)),
            );
            Ok(Behaviour {
                allowed: allow_block_list::Behaviour::default(),
                limits,
                gossipsub,
            })
        })
        .map_err(|e| NetError::Setup(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();
    for p in &cfg.allowed_peers {
        swarm.behaviour_mut().allowed.allow_peer(*p);
    }
    for t in &cfg.subscribe {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(t.clone()))
            .map_err(|e| NetError::Setup(e.to_string()))?;
    }
    for a in &cfg.listen {
        swarm
            .listen_on(a.clone())
            .map_err(|e| NetError::Setup(e.to_string()))?;
    }
    Ok(swarm)
}

/// Starts the network node on the current tokio runtime.
pub fn spawn(keypair: identity::Keypair, cfg: NetConfig) -> Result<NetworkHandle, NetError> {
    if cfg.outbound_bytes_per_sec == Some(0) {
        return Err(NetError::Setup(
            "outbound_bytes_per_sec must be positive (use None for unlimited)".into(),
        ));
    }
    if cfg.per_peer_burst == 0 {
        return Err(NetError::Setup("per_peer_burst must be positive".into()));
    }
    let local_peer_id = keypair.public().to_peer_id();
    let mut swarm = build_swarm(keypair, &cfg)?;
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(cfg.command_queue.max(1));
    let (ev_tx, ev_rx) = mpsc::channel::<NetEvent>(cfg.inbound_queue.max(1));
    let stats = Arc::new(NetStats::default());
    let task_stats = Arc::clone(&stats);
    let mut allowed: HashSet<PeerId> = cfg.allowed_peers.iter().copied().collect();
    let bootstrap = cfg.bootstrap.clone();
    let redial = cfg.redial_interval;
    let mut limiter: RateLimiter<PeerId> = RateLimiter::new(
        cfg.per_peer_burst,
        cfg.per_peer_refill_per_sec,
        allowed.len().max(1) * 2,
    );

    tokio::spawn(async move {
        let started = Instant::now();
        let mut connected: HashMap<PeerId, u32> = HashMap::new();
        let mut ticker = tokio::time::interval(redial);
        let mut penalties = Penalties::default();
        let mut decay_tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        None | Some(Command::Shutdown) => break,
                        Some(Command::Publish { topic, data, reply }) => {
                            let len = data.len() as u64;
                            let res = swarm
                                .behaviour_mut()
                                .gossipsub
                                .publish(IdentTopic::new(topic), data)
                                .map(|_| ())
                                .map_err(|e| match e {
                                    libp2p::gossipsub::PublishError::Duplicate => NetError::Duplicate,
                                    other => NetError::Publish(other.to_string()),
                                });
                            if res.is_ok() {
                                NetStats::add(&task_stats.bytes_out, len);
                                NetStats::add(&task_stats.messages_out, 1);
                            } else {
                                NetStats::add(&task_stats.publish_failures, 1);
                            }
                            let _ = reply.send(res);
                        }
                        Some(Command::SetAllowed(peers)) => {
                            let new: HashSet<PeerId> = peers.into_iter().collect();
                            for p in allowed.difference(&new) {
                                swarm.behaviour_mut().allowed.disallow_peer(*p);
                                info!(peer = %p, "peer no longer allowed; disconnected");
                            }
                            for p in new.difference(&allowed) {
                                swarm.behaviour_mut().allowed.allow_peer(*p);
                            }
                            allowed = new;
                        }
                        Some(Command::PeerScore { peer, reply }) => {
                            let _ = reply.send(swarm.behaviour().gossipsub.peer_score(&peer));
                        }
                        Some(Command::Report { id, source, author, acceptance }) => {
                            // An invalid message counts against its author (who signed it),
                            // never against the peers that relayed it: gossipsub, which would
                            // charge every peer that delivered a copy, is told `Ignore`.
                            let acceptance = if acceptance == Acceptance::Reject {
                                NetStats::add(&task_stats.rejected_by_application, 1);
                                if let Some(a) = author {
                                    let score = penalties.add(a, Instant::now());
                                    swarm.behaviour_mut().gossipsub.set_application_score(&a, score);
                                }
                                Acceptance::Ignore
                            } else {
                                acceptance
                            };
                            let _ = swarm
                                .behaviour_mut()
                                .gossipsub
                                .report_message_validation_result(&id, &source, acceptance.into());
                        }
                        Some(Command::AuthorScore { peer, reply }) => {
                            let _ = reply.send(penalties.score(&peer, Instant::now()));
                        }
                    }
                }
                _ = decay_tick.tick() => {
                    let mut penalised = 0u64;
                    for (p, score) in penalties.refresh(Instant::now()) {
                        if score < 0.0 {
                            penalised += 1;
                        }
                        swarm.behaviour_mut().gossipsub.set_application_score(&p, score);
                    }
                    task_stats.penalised_peers.store(penalised, std::sync::atomic::Ordering::Relaxed);
                }
                _ = ticker.tick() => {
                    for addr in &bootstrap {
                        if let Some(p) = peer_of(addr)
                            && !connected.contains_key(&p)
                            && p != *swarm.local_peer_id()
                        {
                            debug!(%addr, "dialling bootstrap peer");
                            let _ = swarm.dial(addr.clone());
                        }
                    }
                }
                ev = swarm.select_next_some() => {
                    match ev {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(%address, "listening");
                            let _ = ev_tx.try_send(NetEvent::Listening(address));
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                            // Reconnecting does not reset an author's penalty.
                            let score = penalties.score(&peer_id, Instant::now());
                            if score < 0.0 {
                                swarm.behaviour_mut().gossipsub.set_application_score(&peer_id, score);
                            }
                            if num_established.get() == 1 {
                                connected.insert(peer_id, 1);
                                task_stats.connected_peers.store(connected.len() as u64, std::sync::atomic::Ordering::Relaxed);
                                let _ = ev_tx.try_send(NetEvent::PeerConnected(peer_id));
                            }
                        }
                        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                            if num_established == 0 {
                                connected.remove(&peer_id);
                                task_stats.connected_peers.store(connected.len() as u64, std::sync::atomic::Ordering::Relaxed);
                                let _ = ev_tx.try_send(NetEvent::PeerDisconnected(peer_id));
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source,
                            message_id,
                            message,
                        })) => {
                            let len = message.data.len() as u64;
                            NetStats::add(&task_stats.bytes_in, len);
                            NetStats::add(&task_stats.messages_in, 1);
                            let gs = &mut swarm.behaviour_mut().gossipsub;
                            // Authors must be enrolled peers (relays may forward, but the
                            // original author is authenticated by the gossipsub signature).
                            // Dropped without penalty: an honest relay with a newer manifest
                            // forwards authors this node does not know yet.
                            let author_ok = message.source.is_some_and(|a| allowed.contains(&a));
                            if !author_ok {
                                NetStats::add(&task_stats.rejected_unknown_author, 1);
                                let _ = gs.report_message_validation_result(&message_id, &propagation_source, MessageAcceptance::Ignore);
                                continue;
                            }
                            // Rate-limit the authenticated *author*, not the relaying peer, so a
                            // throttled relay cannot cause honest authors' messages to be dropped.
                            let author = message.source.unwrap_or(propagation_source);
                            // A graylisted author is not heard, whichever peer relays it.
                            if penalties.score(&author, Instant::now()) <= GRAYLIST_THRESHOLD {
                                NetStats::add(&task_stats.dropped_penalised, 1);
                                let _ = gs.report_message_validation_result(&message_id, &propagation_source, MessageAcceptance::Ignore);
                                continue;
                            }
                            let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                            let cost = 1 + u32::try_from(len / 1024).unwrap_or(u32::MAX);
                            if !limiter.allow(&author, cost, now_ms) {
                                NetStats::add(&task_stats.dropped_rate_limited, 1);
                                let _ = gs.report_message_validation_result(&message_id, &propagation_source, MessageAcceptance::Ignore);
                                continue;
                            }
                            let inbound = InboundMessage {
                                topic: message.topic.into_string(),
                                data: message.data,
                                propagation_source,
                                author: message.source,
                                message_id: message_id.clone(),
                            };
                            if ev_tx.try_send(NetEvent::Message(inbound)).is_err() {
                                NetStats::add(&task_stats.dropped_queue_full, 1);
                                let _ = gs.report_message_validation_result(&message_id, &propagation_source, MessageAcceptance::Ignore);
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            debug!(?peer_id, %error, "outgoing connection failed");
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            debug!(%error, "incoming connection refused");
                        }
                        _ => {}
                    }
                }
            }
        }
        warn!("network task stopped");
    });

    Ok(NetworkHandle {
        commands: cmd_tx,
        events: Mutex::new(ev_rx),
        local_peer_id,
        stats,
        outbound: cfg
            .outbound_bytes_per_sec
            .map(|r| Mutex::new((r as f64, Instant::now()))),
        outbound_rate: cfg.outbound_bytes_per_sec.unwrap_or(0),
    })
}

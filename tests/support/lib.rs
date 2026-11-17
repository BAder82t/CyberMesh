//! Shared harness: runs a real CyberMesh network (libp2p over 127.0.0.1) inside one process.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_debug_implementations
)]

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use cybermesh_analysis::{Brand, CtLogInfo, Engine, EvidenceBundle};
use cybermesh_crypto::Digest;
use cybermesh_ct::mock::MockLog;
use cybermesh_network::Multiaddr;
use cybermesh_node::coordinator::CtSetup;
use cybermesh_node::coordinator::{
    CoordinatorReport, CoordinatorSetup, prepare_domains, run_coordinator,
};
use cybermesh_node::governor::ResourcePolicy;
use cybermesh_node::verifier::{VerifierReport, VerifierSetup, run_verifier};
use cybermesh_node::worker::{WorkerSetup, WorkerStatus, run_worker};
use cybermesh_protocol::testkit::TestNetwork;
use cybermesh_protocol::{Clock, SystemClock};
use cybermesh_verifier::Policy;
use cybermesh_verifier::ct::CtPolicy;
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub const PHISH: &str = "examplebank-secure-login.phish.localhost";
pub const LEXICAL: &str = "examplebank-account-verify.phish.localhost";

/// Demo evidence shared by every node.
pub fn evidence() -> EvidenceBundle {
    evidence_with_ct(None)
}

/// Demo evidence, optionally pinning one CT log (`mock-log`) at `ct_url`.
pub fn evidence_with_ct(ct_url: Option<&str>) -> EvidenceBundle {
    let feed = [PHISH, "malware-drop.example.net", "www.google.com"];
    EvidenceBundle {
        blocklists: vec![(
            "reference-feed".into(),
            feed.iter().map(|s| (*s).to_owned()).collect(),
        )],
        popular: HashSet::from(["google.com".to_owned(), "wikipedia.org".to_owned()]),
        hosting_platforms: HashSet::new(),
        ct_logs: ct_url
            .map(|u| {
                vec![CtLogInfo {
                    log_id: "mock-log".into(),
                    description: "mock".into(),
                    monitoring_url: u.into(),
                }]
            })
            .unwrap_or_default(),
        brands: vec![Brand {
            name: "examplebank".into(),
            tokens: vec!["examplebank".into()],
            legitimate: vec!["examplebank.test".into()],
        }],
        pins: BTreeMap::from_iter(
            ct_url
                .map(|u| ("ct-logs".to_owned(), Digest::of(u.as_bytes())))
                .into_iter()
                .chain([
                    ("brands".into(), Digest::of(b"brands-v1")),
                    ("popularity".into(), Digest::of(b"popularity-v1")),
                    ("reference-feed".into(), Digest::of(b"feed-v1")),
                ]),
        ),
        sources: vec![],
        skipped_lines: 0,
    }
}

pub fn domains() -> Vec<String> {
    let text = format!(
        "{PHISH}\n{LEXICAL}\nmalware-drop.example.net\nwww.google.com\nwikipedia.org\n\
         examplebank.test\nmail.example.org\nx7kq9zr2mw4tplv.top\nxn--pypal-4ve.com\n\
         paypa1-secure.example.com\nnews.example.co.uk\nshop.example.com\n"
    );
    prepare_domains(&text).0
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running network.
pub struct Harness {
    pub net: TestNetwork,
    pub coordinator: JoinHandle<CoordinatorReport>,
    /// Independent verifiers (operators 1 and 2 of the test network).
    pub verifiers: Vec<(watch::Sender<bool>, JoinHandle<VerifierReport>)>,
    pub workers: Vec<(usize, watch::Sender<bool>, JoinHandle<WorkerStatus>)>,
    pub coord_shutdown: watch::Sender<bool>,
    pub dir: tempfile::TempDir,
}

pub struct Options {
    pub operators: Vec<(&'static str, usize)>,
    /// Worker index -> adversary mode.
    pub adversaries: Vec<(usize, &'static str)>,
    pub replication: usize,
    pub batch_size: usize,
    pub result_timeout: Duration,
    pub abandon_after: Duration,
    pub domains: Vec<String>,
    /// Run a mock CT log and schedule `ct_tiles` full tiles of it.
    pub ct_log: Option<Arc<MockLog>>,
    pub ct_tiles: u64,
    pub ct_tiles_per_task: u32,
    pub ct_replication: usize,
    pub ct_policy: CtPolicy,
    /// Independent verifier nodes to run (0..=2), at operators 1 and 2.
    pub independent_verifiers: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            operators: vec![("org-a", 1), ("org-b", 1), ("org-c", 1), ("org-d", 1)],
            adversaries: vec![],
            replication: 3,
            batch_size: 4,
            result_timeout: Duration::from_secs(6),
            abandon_after: Duration::from_secs(60),
            domains: domains(),
            ct_log: None,
            ct_tiles: 0,
            ct_tiles_per_task: 2,
            ct_replication: 2,
            ct_policy: CtPolicy::default(),
            independent_verifiers: 0,
        }
    }
}

fn test_resources() -> ResourcePolicy {
    // All nodes share one test process, so per-process CPU/memory/load budgets would
    // measure the whole test. Resource limits are tested separately.
    ResourcePolicy {
        cpu_percent: 100.0,
        memory_mb: 1 << 20,
        max_load_per_cpu: f64::MAX,
        outbound_kib_per_sec: 0,
        ct_scanning: true,
        ct_fetch_kib_per_sec: 0,
        ..ResourcePolicy::default()
    }
}

pub fn start_worker(
    net: &TestNetwork,
    i: usize,
    bootstrap: &[Multiaddr],
    dir: &std::path::Path,
    adversary: Option<&str>,
    ct_url: Option<&str>,
) -> (watch::Sender<bool>, JoinHandle<WorkerStatus>) {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let w = &net.workers[i];
    let setup = WorkerSetup {
        key: cybermesh_crypto::SecretKey::from_seed(&w.key.seed()),
        manifest: net.manifest.clone(),
        engine: Engine::new(evidence_with_ct(ct_url)),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: bootstrap.to_vec(),
        state_dir: dir.join(&w.label),
        control_dir: dir.join(&w.label).join("control"),
        heartbeat: Duration::from_millis(700),
        resources: test_resources(),
        clock,
        gossip_heartbeat: Duration::from_millis(100),
        adversary: adversary.map(str::to_owned),
        manifest_source: None,
    };
    let (tx, rx) = watch::channel(false);
    let h = tokio::spawn(async move { run_worker(setup, rx).await.unwrap() });
    (tx, h)
}

impl Harness {
    pub fn start(o: Options) -> Self {
        let now = SystemClock.now();
        let net = TestNetwork::new(&o.operators, now);
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let peer = cybermesh_network::peer_id_of(&net.issuer.public_key()).unwrap();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
            .parse()
            .unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let ct_url = o.ct_log.as_ref().map(|log| {
            let (url, _h) = cybermesh_ct::mock::serve(Arc::clone(log), "127.0.0.1:0").unwrap();
            url
        });
        let ct = ct_url.as_ref().map(|u| CtSetup {
            log: CtLogInfo {
                log_id: "mock-log".into(),
                description: "mock".into(),
                monitoring_url: u.clone(),
            },
            first_tile: Some(0),
            tile_count: o.ct_tiles,
            tiles_per_task: o.ct_tiles_per_task,
            replication: o.ct_replication,
            policy: o.ct_policy.clone(),
            seed: [7u8; 32],
        });
        let setup = CoordinatorSetup {
            issuer: cybermesh_crypto::SecretKey::from_seed(&net.issuer.seed()),
            verifier: cybermesh_crypto::SecretKey::from_seed(&net.verifier.seed()),
            manifest: net.manifest.clone(),
            engine: Engine::new(evidence_with_ct(ct_url.as_deref())),
            listen: vec![format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()],
            bootstrap: vec![],
            state_dir: dir.path().join("coordinator"),
            domains: o.domains.clone(),
            batch_size: o.batch_size,
            replication: o.replication,
            task_ttl_secs: 300,
            result_timeout: o.result_timeout,
            max_attempts: 3,
            liveness_secs: 30,
            max_inflight: 4,
            exit_when_done: true,
            abandon_after: o.abandon_after,
            policy: Policy::default(),
            clock,
            gossip_heartbeat: Duration::from_millis(100),
            manifest_source: None,
            ct,
        };
        let (ctx, crx) = watch::channel(false);
        // Independent verifiers dial the coordinator; workers dial both, so results reach a
        // verifier directly as well as through the coordinator.
        let mut verifiers = Vec::new();
        let mut worker_bootstrap = vec![addr.clone()];
        for (key, op) in net.other_verifiers.iter().take(o.independent_verifiers) {
            let vport = free_port();
            let vpeer = cybermesh_network::peer_id_of(&key.public_key()).unwrap();
            worker_bootstrap.push(
                format!("/ip4/127.0.0.1/tcp/{vport}/p2p/{vpeer}")
                    .parse()
                    .unwrap(),
            );
            let vsetup = VerifierSetup {
                key: cybermesh_crypto::SecretKey::from_seed(&key.seed()),
                manifest: net.manifest.clone(),
                engine: Engine::new(evidence_with_ct(ct_url.as_deref())),
                listen: vec![format!("/ip4/127.0.0.1/tcp/{vport}").parse().unwrap()],
                bootstrap: vec![addr.clone()],
                state_dir: dir.path().join(format!("verifier-{op}")),
                result_timeout: o.result_timeout,
                policy: Policy::default(),
                ct_policy: o.ct_policy.clone(),
                // A different secret seed from the coordinator's.
                ct_seed: [9u8; 32],
                clock: Arc::new(SystemClock),
                gossip_heartbeat: Duration::from_millis(100),
                manifest_source: None,
                idle_exit: Some(Duration::from_secs(3)),
            };
            let (vtx, vrx) = watch::channel(false);
            verifiers.push((
                vtx,
                tokio::spawn(async move { run_verifier(vsetup, vrx).await.unwrap() }),
            ));
        }
        let coordinator = tokio::spawn(async move { run_coordinator(setup, crx).await.unwrap() });
        let mut workers = Vec::new();
        for i in 0..net.workers.len() {
            let adv = o.adversaries.iter().find(|(w, _)| *w == i).map(|(_, m)| *m);
            let (tx, h) = start_worker(
                &net,
                i,
                &worker_bootstrap,
                dir.path(),
                adv,
                ct_url.as_deref(),
            );
            workers.push((i, tx, h));
        }
        Self {
            net,
            coordinator,
            verifiers,
            workers,
            coord_shutdown: ctx,
            dir,
        }
    }

    /// Waits for the coordinator to settle everything, then stops all workers.
    pub async fn finish(
        self,
        within: Duration,
    ) -> (
        TestNetwork,
        CoordinatorReport,
        Vec<WorkerStatus>,
        tempfile::TempDir,
    ) {
        let (net, report, statuses, _, dir) = self.finish_all(within).await;
        (net, report, statuses, dir)
    }

    /// As [`Harness::finish`], also waiting for the independent verifiers to go idle.
    pub async fn finish_all(
        self,
        within: Duration,
    ) -> (
        TestNetwork,
        CoordinatorReport,
        Vec<WorkerStatus>,
        Vec<VerifierReport>,
        tempfile::TempDir,
    ) {
        let report = tokio::time::timeout(within, self.coordinator)
            .await
            .expect("coordinator did not finish in time")
            .unwrap();
        let mut verifier_reports = Vec::new();
        for (tx, h) in self.verifiers {
            // Each verifier exits once idle; it may still be settling its last tasks.
            let r = tokio::time::timeout(Duration::from_secs(60), h)
                .await
                .expect("verifier did not finish in time")
                .unwrap();
            let _ = tx.send(true);
            verifier_reports.push(r);
        }
        let mut statuses = Vec::new();
        for (_, tx, h) in self.workers {
            let _ = tx.send(true);
            if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(10), h).await {
                statuses.push(s);
            }
        }
        let _ = self.coord_shutdown;
        (self.net, report, statuses, verifier_reports, self.dir)
    }
}

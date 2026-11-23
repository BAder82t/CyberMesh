//! `cybermesh doctor`: a read-only self-check of a node before it joins the network.
//!
//! It reads a worker, verifier or coordinator configuration and reports, one line each, whether
//! the files it names are usable and whether the node would be admitted: keys, governance root,
//! the signed trust manifest (valid, for this network, not close to expiry, not older than the
//! one last accepted), this key's enrolment, evidence, the state directory, the ports it will
//! listen on, and the bootstrap peers (known to the manifest, and reachable).
//!
//! It never changes configuration, keys, the manifest state or the evidence. Its only writes
//! are a probe file that it creates and removes in an existing state directory, and a listener
//! bound for an instant to each configured port. The only network traffic is one TCP connection
//! to each bootstrap address already in the configuration, and `probe = false` switches that off.

use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use cybermesh_crypto::{KeyId, SecretKey};
use cybermesh_network::{Multiaddr, PeerId, peer_id_of};
use cybermesh_protocol::{Role, TrustManifest};
use serde::Serialize;

use crate::config::{CoordinatorConfig, VerifierConfig, WorkerConfig};
use crate::files::{self, ManifestState};
use crate::governor::ResourcePolicy;
use crate::worker::allowed_peers;

/// A manifest with fewer seconds than this left earns a warning, as in the node's own log.
pub const EXPIRY_WARNING_SECS: u64 = crate::expiry::WARN_WITHIN_SECS;
/// A clock this many seconds behind the manifest's issue time earns a warning.
const CLOCK_SKEW_SECS: u64 = 300;

/// Which kind of node a configuration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    Worker,
    Verifier,
    Coordinator,
}

impl NodeKind {
    fn name(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Verifier => "verifier",
            Self::Coordinator => "coordinator",
        }
    }

    /// Guesses the kind from the keys of a configuration file.
    #[must_use]
    pub fn detect(text: &str) -> Option<Self> {
        let t: toml::Table = toml::from_str(text).ok()?;
        if t.contains_key("issuer_key") {
            Some(Self::Coordinator)
        } else if t.contains_key("control_dir") {
            Some(Self::Worker)
        } else if t.contains_key("key") {
            Some(Self::Verifier)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

/// One line of the report.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    /// What to do about a warning or failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Ok,
            detail: detail.into(),
            fix: None,
        }
    }

    fn warn(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }

    fn fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

/// Everything `doctor` found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub config: String,
    pub kind: Option<NodeKind>,
    pub checks: Vec<Check>,
}

impl Report {
    #[must_use]
    pub fn count(&self, s: Status) -> usize {
        self.checks.iter().filter(|c| c.status == s).count()
    }

    /// Whether anything failed (warnings do not count).
    #[must_use]
    pub fn failed(&self) -> bool {
        self.count(Status::Fail) > 0
    }

    /// The report as text, one line per check and an indented fix under each problem.
    #[must_use]
    pub fn render(&self) -> String {
        let kind = self.kind.map_or("node", NodeKind::name);
        let mut out = format!("CyberMesh doctor: {kind} configuration {}\n\n", self.config);
        let width = self.checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
        for c in &self.checks {
            let tag = match c.status {
                Status::Ok => "ok  ",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
            };
            out.push_str(&format!("  {tag}  {:width$}  {}\n", c.name, c.detail));
            if let Some(fix) = &c.fix {
                out.push_str(&format!("        {:width$}  fix: {fix}\n", ""));
            }
        }
        out.push_str(&format!(
            "\n{} ok, {} warning(s), {} failed\n",
            self.count(Status::Ok),
            self.count(Status::Warn),
            self.count(Status::Fail)
        ));
        out
    }
}

/// How `doctor` runs.
#[derive(Debug, Clone)]
pub struct Options {
    /// Unix seconds now.
    pub now: u64,
    /// Open a TCP connection to each bootstrap address (nothing is sent).
    pub probe: bool,
    pub probe_timeout: Duration,
}

/// What every node kind has in common, as far as the checks go.
struct Node {
    kind: NodeKind,
    network_id: String,
    /// Label, key file, and the role the manifest must give it.
    keys: Vec<(&'static str, PathBuf, Role)>,
    manifest: PathBuf,
    governance_root: PathBuf,
    evidence_dir: PathBuf,
    state_dir: PathBuf,
    listen: Vec<String>,
    bootstrap: Vec<String>,
    control_dir: Option<PathBuf>,
    domains_file: Option<PathBuf>,
    resources: Option<ResourcePolicy>,
}

fn load_node(path: &Path, kind: Option<NodeKind>) -> Result<Node, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let kind = kind.or_else(|| NodeKind::detect(&text)).ok_or_else(|| {
        "cannot tell whether this is a worker, verifier or coordinator configuration (pass --role)"
            .to_owned()
    })?;
    let e = |err: crate::NodeError| err.to_string();
    Ok(match kind {
        NodeKind::Worker => {
            let c = WorkerConfig::load(path).map_err(e)?;
            Node {
                kind,
                network_id: c.network_id,
                keys: vec![("worker key", c.key, Role::Worker)],
                manifest: c.manifest,
                governance_root: c.governance_root,
                evidence_dir: c.evidence_dir,
                state_dir: c.state_dir,
                listen: c.listen,
                bootstrap: c.bootstrap,
                control_dir: Some(c.control_dir),
                domains_file: None,
                resources: Some(c.resources),
            }
        }
        NodeKind::Verifier => {
            let c = VerifierConfig::load(path).map_err(e)?;
            Node {
                kind,
                network_id: c.network_id,
                keys: vec![("verifier key", c.key, Role::Verifier)],
                manifest: c.manifest,
                governance_root: c.governance_root,
                evidence_dir: c.evidence_dir,
                state_dir: c.state_dir,
                listen: c.listen,
                bootstrap: c.bootstrap,
                control_dir: None,
                domains_file: None,
                resources: None,
            }
        }
        NodeKind::Coordinator => {
            let c = CoordinatorConfig::load(path).map_err(e)?;
            Node {
                kind,
                network_id: c.network_id,
                keys: vec![
                    ("issuer key", c.issuer_key, Role::Issuer),
                    ("verifier key", c.verifier_key, Role::Verifier),
                ],
                manifest: c.manifest,
                governance_root: c.governance_root,
                evidence_dir: c.evidence_dir,
                state_dir: c.state_dir,
                listen: c.listen,
                bootstrap: c.bootstrap,
                control_dir: None,
                domains_file: Some(c.domains_file),
                resources: None,
            }
        }
    })
}

/// Checks the configuration at `config`. `kind` is guessed from the file when `None`.
#[must_use]
pub fn run(config: &Path, kind: Option<NodeKind>, opts: &Options) -> Report {
    let mut report = Report {
        config: config.display().to_string(),
        kind,
        checks: Vec::new(),
    };
    let node = match load_node(config, kind) {
        Ok(n) => n,
        Err(e) => {
            let fix = if e.contains("No such file") {
                "check the path given to --config"
            } else {
                "fix the file (see docs/operator-guide.md), then run doctor again"
            };
            report.checks.push(Check::fail("configuration", e, fix));
            return report;
        }
    };
    report.kind = Some(node.kind);
    report.checks.push(Check::ok(
        "configuration",
        format!(
            "read as a {} configuration for network {}",
            node.kind.name(),
            node.network_id
        ),
    ));
    let checks = &mut report.checks;
    let keys = check_keys(&node, checks);
    let manifest = check_manifest(&node, opts.now, checks);
    if let Some(m) = &manifest {
        check_enrolment(&node, &keys, m, checks);
    }
    check_evidence(&node, checks);
    check_state_dir(&node, checks);
    check_listen(&node, checks);
    check_bootstrap(&node, &keys, manifest.as_ref(), opts, checks);
    check_extras(&node, opts.now, checks);
    report
}

/// A key that loaded: its label, role, id and peer id.
struct LoadedKey {
    label: &'static str,
    role: Role,
    id: KeyId,
}

fn check_keys(node: &Node, checks: &mut Vec<Check>) -> Vec<LoadedKey> {
    let mut loaded = Vec::new();
    for (label, path, role) in &node.keys {
        if !path.exists() {
            checks.push(Check::fail(
                label,
                format!("{} does not exist", path.display()),
                "create it with `cybermesh keygen` and send governance only the public key",
            ));
            continue;
        }
        match SecretKey::read_from_file(path) {
            Err(e) => {
                let msg = e.to_string();
                // A node refuses a key file that group or others can read, exactly so.
                let fix = if msg.contains("group/others") {
                    format!("chmod 600 {}", path.display())
                } else {
                    "the file must be a key written by `cybermesh keygen`".to_owned()
                };
                checks.push(Check::fail(label, msg, fix));
            }
            Ok(sk) => {
                let id = sk.key_id();
                let peer =
                    peer_id_of(&sk.public_key()).map_or_else(|_| "?".into(), |p| p.to_string());
                checks.push(Check::ok(
                    label,
                    format!("key id {}, peer id {peer}", id.short()),
                ));
                loaded.push(LoadedKey {
                    label,
                    role: *role,
                    id,
                });
            }
        }
    }
    loaded
}

use crate::expiry::duration_text;

fn check_manifest(node: &Node, now: u64, checks: &mut Vec<Check>) -> Option<TrustManifest> {
    if !node.governance_root.exists() {
        checks.push(Check::fail(
            "governance root",
            format!("{} does not exist", node.governance_root.display()),
            "get the pinned governance root from the network's governance, out of band",
        ));
        return None;
    }
    let (m, root) = match files::load_manifest(&node.manifest, &node.governance_root, now) {
        Ok(x) => x,
        Err(e) => {
            checks.push(Check::fail(
                "manifest",
                format!("{}: {e}", node.manifest.display()),
                "ask governance for the current signed manifest; if it has expired, for a renewed one",
            ));
            return None;
        }
    };
    checks.push(Check::ok(
        "governance root",
        format!(
            "network {}, {} of its keys must sign",
            root.network_id, root.threshold
        ),
    ));
    if m.network_id != node.network_id {
        checks.push(Check::fail(
            "manifest",
            format!(
                "it is for network {}, the configuration says {}",
                m.network_id, node.network_id
            ),
            "use the manifest and network_id of the network you are joining",
        ));
        return Some(m);
    }
    let left = m.expires_at.saturating_sub(now);
    let detail = format!(
        "sequence {}, signed by governance, expires in {}",
        m.sequence,
        duration_text(left)
    );
    if left < EXPIRY_WARNING_SECS {
        checks.push(Check::warn(
            "manifest",
            detail,
            "ask governance for a renewed manifest before it expires: a node stops accepting tasks then",
        ));
    } else {
        checks.push(Check::ok("manifest", detail));
    }
    if now + CLOCK_SKEW_SECS < m.issued_at {
        checks.push(Check::warn(
            "clock",
            format!(
                "this machine's clock is {} behind the manifest's issue time",
                duration_text(m.issued_at - now)
            ),
            "set the clock with NTP: signed messages are refused when the clocks disagree",
        ));
    } else {
        checks.push(Check::ok(
            "clock",
            "not behind the manifest's issue time (the network's clocks are not queried)",
        ));
    }
    check_rollback(node, &m, checks);
    Some(m)
}

fn check_rollback(node: &Node, m: &TrustManifest, checks: &mut Vec<Check>) {
    let path = node.state_dir.join("manifest-state.json");
    if !path.exists() {
        checks.push(Check::ok(
            "manifest history",
            "no manifest accepted before (first start)",
        ));
        return;
    }
    match files::read_json::<ManifestState>(&path) {
        Err(e) => checks.push(Check::fail(
            "manifest history",
            format!("{}: {e}", path.display()),
            "the file records the newest manifest this node accepted; restore it from a backup rather than deleting it",
        )),
        Ok(s) if s.sequence > m.sequence => checks.push(Check::fail(
            "manifest history",
            format!(
                "this node already accepted sequence {}, the manifest is {}: it would refuse it",
                s.sequence, m.sequence
            ),
            "use the newest manifest from governance (a node never goes back to an older one)",
        )),
        Ok(s) => checks.push(Check::ok(
            "manifest history",
            format!("newest accepted before: sequence {}", s.sequence),
        )),
    }
}

fn check_enrolment(node: &Node, keys: &[LoadedKey], m: &TrustManifest, checks: &mut Vec<Check>) {
    if m.network_id != node.network_id {
        return;
    }
    for k in keys {
        let name = format!("{} enrolment", k.label);
        if m.key_with_role(&k.id, k.role).is_some() {
            checks.push(Check::ok(&name, "enrolled in the manifest with this role"));
        } else if m.is_revoked(&k.id) {
            checks.push(Check::fail(
                &name,
                "this key has been revoked",
                "generate a new key and ask governance to enrol it",
            ));
        } else if m.members.iter().any(|x| x.public_key.key_id() == k.id) {
            checks.push(Check::fail(
                &name,
                "the key is enrolled, but not with the role this node needs",
                "ask governance to enrol it for the right role",
            ));
        } else {
            checks.push(Check::fail(
                &name,
                format!("key {} is not in the manifest", k.id.short()),
                "send governance the public key (`cybermesh key-info`) and wait for a manifest that lists it",
            ));
        }
    }
}

fn check_evidence(node: &Node, checks: &mut Vec<Check>) {
    match cybermesh_analysis::EvidenceBundle::load(&node.evidence_dir) {
        Ok(_) => checks.push(Check::ok(
            "evidence",
            format!(
                "{} loads and every file matches its pinned digest",
                node.evidence_dir.display()
            ),
        )),
        Err(e) => checks.push(Check::fail(
            "evidence",
            format!("{}: {e}", node.evidence_dir.display()),
            "use the evidence bundle the network published, unchanged",
        )),
    }
}

fn check_state_dir(node: &Node, checks: &mut Vec<Check>) {
    let dir = &node.state_dir;
    if !dir.exists() {
        let parent_ok = dir.parent().is_some_and(Path::is_dir);
        checks.push(if parent_ok {
            Check::ok(
                "state directory",
                format!("{} does not exist yet; the node creates it", dir.display()),
            )
        } else {
            Check::fail(
                "state directory",
                format!("{} and its parent do not exist", dir.display()),
                "create the directory, owned by the account the node runs as",
            )
        });
        return;
    }
    let probe = dir.join(format!(".doctor-probe-{}", std::process::id()));
    let writable = std::fs::write(&probe, b"doctor").is_ok();
    let _ = std::fs::remove_file(&probe);
    if !writable {
        checks.push(Check::fail(
            "state directory",
            format!("{} is not writable by this account", dir.display()),
            "make it writable by the account that runs the node",
        ));
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = std::fs::metadata(dir) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o022 != 0 {
                checks.push(Check::warn(
                    "state directory",
                    format!(
                        "{} can be written by other users (mode {mode:o})",
                        dir.display()
                    ),
                    format!("chmod 700 {}", dir.display()),
                ));
                return;
            }
        }
    }
    checks.push(Check::ok(
        "state directory",
        format!("{} is writable", dir.display()),
    ));
}

/// Host, port and peer id of a `/ip4|ip6|dns|dns4|dns6/<host>/tcp/<port>[/p2p/<id>]` address.
struct Parsed {
    host: String,
    port: u16,
    peer: Option<String>,
}

fn parse_addr(s: &str) -> Result<Parsed, String> {
    s.parse::<Multiaddr>()
        .map_err(|e| format!("not a valid address: {e}"))?;
    let parts: Vec<&str> = s.split('/').skip(1).collect();
    let mut p = Parsed {
        host: String::new(),
        port: 0,
        peer: None,
    };
    for pair in parts.chunks(2) {
        match pair {
            ["ip4" | "ip6" | "dns" | "dns4" | "dns6", host] => p.host = (*host).to_owned(),
            ["tcp", port] => p.port = port.parse().map_err(|_| "bad tcp port".to_owned())?,
            ["p2p", id] => p.peer = Some((*id).to_owned()),
            _ => {}
        }
    }
    if p.host.is_empty() || p.port == 0 {
        return Err("needs a host and a tcp port (for example /ip4/192.0.2.1/tcp/4100)".into());
    }
    Ok(p)
}

fn check_listen(node: &Node, checks: &mut Vec<Check>) {
    if node.listen.is_empty() {
        checks.push(Check::warn(
            "listen",
            "no listen address: the node can dial out but nobody can dial it",
            "fine for a worker behind NAT; add `listen` if other nodes should reach it",
        ));
        return;
    }
    for a in &node.listen {
        let p = match parse_addr(a) {
            Ok(p) => p,
            Err(e) => {
                checks.push(Check::fail(
                    "listen",
                    format!("{a}: {e}"),
                    "use /ip4/<address>/tcp/<port>",
                ));
                continue;
            }
        };
        let Ok(ip) = p.host.parse::<std::net::IpAddr>() else {
            checks.push(Check::warn(
                "listen",
                format!("{a}: a host name cannot be bound"),
                "use an IP address, or 0.0.0.0 for every interface",
            ));
            continue;
        };
        match TcpListener::bind(SocketAddr::new(ip, p.port)) {
            Ok(l) => {
                drop(l);
                checks.push(Check::ok("listen", format!("{a} can be bound")));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => checks.push(Check::warn(
                "listen",
                format!("{a} is already in use"),
                "fine if this node is already running; otherwise pick another port",
            )),
            Err(e) => checks.push(Check::fail(
                "listen",
                format!("{a}: {e}"),
                "pick an address this machine has and a port this account may use",
            )),
        }
    }
}

fn reachable(host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?;
    let mut last = format!("{host} resolves to nothing");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(_) => return Ok(()),
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    Err(last)
}

fn check_bootstrap(
    node: &Node,
    keys: &[LoadedKey],
    manifest: Option<&TrustManifest>,
    opts: &Options,
    checks: &mut Vec<Check>,
) {
    if node.bootstrap.is_empty() {
        checks.push(if node.kind == NodeKind::Coordinator {
            Check::ok(
                "bootstrap",
                "none: the coordinator waits for the others to dial it",
            )
        } else {
            Check::fail(
                "bootstrap",
                "no bootstrap peers: the node has no way to find the network",
                "add the coordinator's address, with its /p2p/<peer id>, to `bootstrap`",
            )
        });
        return;
    }
    let me = keys.first().map(|k| k.id.clone());
    let allowed: Vec<PeerId> = match (manifest, me) {
        (Some(m), Some(me)) => allowed_peers(m, &me),
        _ => Vec::new(),
    };
    for a in &node.bootstrap {
        let p = match parse_addr(a) {
            Ok(p) => p,
            Err(e) => {
                checks.push(Check::fail(
                    "bootstrap",
                    format!("{a}: {e}"),
                    "use /ip4/<address>/tcp/<port>/p2p/<peer id> (or /dns4/<name>/...)",
                ));
                continue;
            }
        };
        let Some(peer) = &p.peer else {
            checks.push(Check::fail(
                "bootstrap",
                format!("{a}: no /p2p/<peer id>"),
                "the peer id is what authenticates the peer: add it",
            ));
            continue;
        };
        if manifest.is_some() && !allowed.iter().any(|x| &x.to_string() == peer) {
            checks.push(Check::warn(
                "bootstrap",
                format!("{a}: peer id {peer} is not an enrolled key of the manifest"),
                "this node would refuse that peer: check the peer id with the operator of that node",
            ));
            continue;
        }
        if !opts.probe {
            checks.push(Check::ok(
                "bootstrap",
                format!("{a} is a known peer (not probed)"),
            ));
            continue;
        }
        match reachable(&p.host, p.port, opts.probe_timeout) {
            Ok(()) => checks.push(Check::ok(
                "bootstrap",
                format!("{a} is a known peer and accepts connections"),
            )),
            Err(e) => checks.push(Check::warn(
                "bootstrap",
                format!("{a} is a known peer but {e}"),
                "check the address, the firewall and DNS; the peer may also be down for now",
            )),
        }
    }
}

fn check_extras(node: &Node, now: u64, checks: &mut Vec<Check>) {
    if let Some(dir) = &node.control_dir {
        let (pause, stop) = (dir.join("PAUSE").exists(), dir.join("STOP").exists());
        if stop || pause {
            checks.push(Check::warn(
                "control directory",
                format!(
                    "{} is present in {}",
                    if stop { "STOP" } else { "PAUSE" },
                    dir.display()
                ),
                "remove the file to let the node work",
            ));
        } else {
            checks.push(Check::ok(
                "control directory",
                format!("no PAUSE or STOP file in {}", dir.display()),
            ));
        }
    }
    if let Some(r) = &node.resources {
        let hours = if r.active_hours_utc.is_empty() || r.within_hours(now) {
            "inside its active hours now"
        } else {
            "outside its active hours now, so it idles"
        };
        checks.push(Check::ok(
            "resources",
            format!(
                "up to {}% of one core, {} MiB, queue {}, {hours}",
                r.cpu_percent, r.memory_mb, r.max_queue
            ),
        ));
    }
    if let Some(f) = &node.domains_file {
        match std::fs::read_to_string(f) {
            Ok(t) if t.lines().any(|l| !l.trim().is_empty()) => checks.push(Check::ok(
                "domains file",
                format!("{} lists domains to assess", f.display()),
            )),
            Ok(_) => checks.push(Check::warn(
                "domains file",
                format!("{} is empty", f.display()),
                "add the domains to assess, one per line",
            )),
            Err(e) => checks.push(Check::fail(
                "domains file",
                format!("{}: {e}", f.display()),
                "create it, or change `domains_file`",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::net::TcpListener;

    use cybermesh_protocol::testkit::TestNetwork;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    /// A worker configuration on disk, with real signed files, and the means to change them.
    struct Fixture {
        dir: tempfile::TempDir,
        net: TestNetwork,
        /// A coordinator listening on loopback, which the worker is told to dial.
        _coordinator: TcpListener,
        bootstrap: String,
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    impl Fixture {
        fn new() -> Self {
            let net = TestNetwork::new(&[("org-a", 1), ("org-b", 1)], NOW);
            let coordinator = TcpListener::bind("127.0.0.1:0").unwrap();
            let peer = peer_id_of(&net.issuer.public_key()).unwrap();
            let bootstrap = format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{peer}",
                coordinator.local_addr().unwrap().port()
            );
            let f = Self {
                dir: tempfile::tempdir().unwrap(),
                net,
                _coordinator: coordinator,
                bootstrap,
            };
            f.write_all();
            f
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn write_all(&self) {
            self.net.workers[0]
                .key
                .write_to_file(&self.path("worker.key.json"))
                .unwrap();
            std::fs::write(
                self.path("governance-root.json"),
                serde_json::to_vec(&self.net.root).unwrap(),
            )
            .unwrap();
            self.write_manifest();
            std::fs::create_dir_all(self.path("state")).unwrap();
            std::fs::create_dir_all(self.path("control")).unwrap();
            self.write_config(&self.bootstrap.clone());
        }

        fn write_manifest(&self) {
            std::fs::write(
                self.path("manifest.json"),
                self.net.manifest_envelope.to_vec().unwrap(),
            )
            .unwrap();
        }

        fn write_config(&self, bootstrap: &str) {
            let evidence =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../datasets/demo/evidence");
            let bootstrap = if bootstrap.is_empty() {
                String::new()
            } else {
                format!("\"{bootstrap}\"")
            };
            std::fs::write(
                self.path("worker.toml"),
                format!(
                    "network_id = \"cybermesh-test\"\nkey = \"worker.key.json\"\nmanifest = \"manifest.json\"\n\
                     governance_root = \"governance-root.json\"\nevidence_dir = \"{}\"\nstate_dir = \"state\"\n\
                     control_dir = \"control\"\nlisten = [\"/ip4/127.0.0.1/tcp/{}\"]\nbootstrap = [{bootstrap}]\n",
                    evidence.display(),
                    free_port()
                ),
            )
            .unwrap();
        }

        fn run(&self, now: u64, probe: bool) -> Report {
            run(
                &self.path("worker.toml"),
                None,
                &Options {
                    now,
                    probe,
                    probe_timeout: Duration::from_secs(2),
                },
            )
        }
    }

    fn check<'a>(r: &'a Report, name: &str) -> &'a Check {
        r.checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check {name}: {}", r.render()))
    }

    fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    v.push((p.display().to_string(), std::fs::read(&p).unwrap()));
                }
            }
        }
        v.sort();
        v
    }

    #[test]
    fn a_healthy_worker_passes_every_check() {
        let f = Fixture::new();
        let r = f.run(NOW + 60, true);
        assert_eq!(r.kind, Some(NodeKind::Worker));
        assert_eq!(
            (r.count(Status::Fail), r.count(Status::Warn)),
            (0, 0),
            "{}",
            r.render()
        );
        for name in [
            "worker key",
            "manifest",
            "worker key enrolment",
            "evidence",
            "bootstrap",
            "listen",
        ] {
            assert_eq!(check(&r, name).status, Status::Ok, "{name}: {}", r.render());
        }
        assert!(
            check(&r, "bootstrap")
                .detail
                .contains("accepts connections")
        );
    }

    #[test]
    fn it_changes_nothing() {
        let f = Fixture::new();
        let before = snapshot(f.dir.path());
        let _ = f.run(NOW + 60, true);
        let _ = f.run(NOW + 60, false);
        assert_eq!(snapshot(f.dir.path()), before, "files changed or appeared");
        // In particular it does not record the manifest as accepted, as starting a node does.
        assert!(!f.path("state/manifest-state.json").exists());
    }

    #[test]
    fn the_kind_is_read_from_the_file() {
        assert_eq!(
            NodeKind::detect("key = \"k\"\ncontrol_dir = \"c\"\n"),
            Some(NodeKind::Worker)
        );
        assert_eq!(NodeKind::detect("key = \"k\"\n"), Some(NodeKind::Verifier));
        assert_eq!(
            NodeKind::detect("issuer_key = \"i\"\nkey = \"k\"\n"),
            Some(NodeKind::Coordinator)
        );
        assert_eq!(NodeKind::detect("name = \"x\"\n"), None);
        assert_eq!(NodeKind::detect("not toml ==="), None);
    }

    #[test]
    fn an_unreadable_configuration_is_one_clear_failure() {
        let f = Fixture::new();
        let r = run(
            &f.path("missing.toml"),
            None,
            &Options {
                now: NOW,
                probe: false,
                probe_timeout: Duration::from_secs(1),
            },
        );
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].status, Status::Fail);
        assert!(r.failed());
    }

    #[test]
    fn a_manifest_close_to_expiry_warns_and_an_expired_one_fails() {
        let f = Fixture::new();
        let expires = f.net.manifest.expires_at;
        let r = f.run(expires - 3 * 86_400, false);
        let c = check(&r, "manifest");
        assert_eq!(c.status, Status::Warn, "{}", r.render());
        assert!(c.detail.contains("3 day"), "{}", c.detail);
        assert!(!r.failed());
        let r = f.run(expires + 1, false);
        assert_eq!(check(&r, "manifest").status, Status::Fail, "{}", r.render());
        assert!(r.failed());
    }

    #[test]
    fn a_manifest_for_another_network_fails() {
        let f = Fixture::new();
        let cfg = std::fs::read_to_string(f.path("worker.toml")).unwrap();
        std::fs::write(
            f.path("worker.toml"),
            cfg.replace("cybermesh-test", "another-network"),
        )
        .unwrap();
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "manifest").status, Status::Fail, "{}", r.render());
    }

    #[test]
    fn a_key_the_manifest_does_not_list_fails_with_what_to_do() {
        let f = Fixture::new();
        std::fs::remove_file(f.path("worker.key.json")).unwrap();
        SecretKey::generate()
            .unwrap()
            .write_to_file(&f.path("worker.key.json"))
            .unwrap();
        let r = f.run(NOW + 60, false);
        let c = check(&r, "worker key enrolment");
        assert_eq!(c.status, Status::Fail);
        assert!(c.fix.as_deref().unwrap().contains("key-info"), "{c:?}");
        // An issuer key is listed, but not for the worker role.
        std::fs::remove_file(f.path("worker.key.json")).unwrap();
        f.net
            .issuer
            .write_to_file(&f.path("worker.key.json"))
            .unwrap();
        let r = f.run(NOW + 60, false);
        assert!(
            check(&r, "worker key enrolment")
                .detail
                .contains("not with the role")
        );
    }

    #[test]
    fn a_manifest_older_than_the_one_accepted_before_would_be_refused() {
        let f = Fixture::new();
        files::write_json(
            &f.path("state/manifest-state.json"),
            &ManifestState {
                sequence: 9,
                digest: cybermesh_crypto::Digest::of(b"x"),
            },
        )
        .unwrap();
        let r = f.run(NOW + 60, false);
        let c = check(&r, "manifest history");
        assert_eq!(c.status, Status::Fail, "{}", r.render());
        assert!(c.detail.contains("sequence 9"));
    }

    #[test]
    fn bootstrap_addresses_are_checked_for_peer_id_membership_and_reachability() {
        let f = Fixture::new();
        // No peer id.
        f.write_config("/ip4/127.0.0.1/tcp/4100");
        let r = f.run(NOW + 60, false);
        assert_eq!(
            check(&r, "bootstrap").status,
            Status::Fail,
            "{}",
            r.render()
        );
        // A peer id the manifest does not list.
        let stranger = peer_id_of(&SecretKey::generate().unwrap().public_key()).unwrap();
        f.write_config(&format!("/ip4/127.0.0.1/tcp/4100/p2p/{stranger}"));
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "bootstrap").status, Status::Warn);
        assert!(
            check(&r, "bootstrap")
                .detail
                .contains("not an enrolled key")
        );
        // A listed peer nobody listens for: a warning with a probe, and fine without one.
        let peer = peer_id_of(&f.net.issuer.public_key()).unwrap();
        f.write_config(&format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer}", free_port()));
        let r = f.run(NOW + 60, true);
        assert_eq!(
            check(&r, "bootstrap").status,
            Status::Warn,
            "{}",
            r.render()
        );
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "bootstrap").status, Status::Ok);
        assert!(check(&r, "bootstrap").detail.contains("not probed"));
        // A worker with no bootstrap peers cannot find the network.
        f.write_config("");
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "bootstrap").status, Status::Fail);
    }

    #[test]
    #[cfg(unix)]
    fn a_key_file_other_users_can_read_is_refused_as_the_node_would() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = Fixture::new();
        let p = f.path("worker.key.json");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = f.run(NOW + 60, false);
        let c = check(&r, "worker key");
        assert_eq!(c.status, Status::Fail, "{}", r.render());
        assert!(c.fix.as_deref().unwrap().starts_with("chmod 600"), "{c:?}");
        // A missing key file says how to make one.
        std::fs::remove_file(&p).unwrap();
        let r = f.run(NOW + 60, false);
        let c = check(&r, "worker key");
        assert_eq!(c.status, Status::Fail);
        assert!(c.fix.as_deref().unwrap().contains("keygen"));
    }

    #[test]
    #[cfg(unix)]
    fn a_state_directory_other_users_can_write_warns() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = Fixture::new();
        std::fs::set_permissions(f.path("state"), std::fs::Permissions::from_mode(0o777)).unwrap();
        let r = f.run(NOW + 60, false);
        let c = check(&r, "state directory");
        assert_eq!(c.status, Status::Warn, "{}", r.render());
        assert!(c.fix.as_deref().unwrap().starts_with("chmod 700"));
        // Only readable by others is not a problem: no key or secret seed is stored there (the
        // verifier's CT seed is random at each start).
        std::fs::set_permissions(f.path("state"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "state directory").status, Status::Ok);
    }

    #[test]
    fn a_paused_node_and_a_busy_port_warn_without_failing() {
        let f = Fixture::new();
        std::fs::write(f.path("control/PAUSE"), b"").unwrap();
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "control directory").status, Status::Warn);
        // The listen port is in use (as it is while the node itself runs).
        let busy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = busy.local_addr().unwrap().port();
        let cfg = std::fs::read_to_string(f.path("worker.toml")).unwrap();
        let old = cfg
            .lines()
            .find(|l| l.starts_with("listen"))
            .unwrap()
            .to_owned();
        std::fs::write(
            f.path("worker.toml"),
            cfg.replace(&old, &format!("listen = [\"/ip4/127.0.0.1/tcp/{port}\"]")),
        )
        .unwrap();
        let r = f.run(NOW + 60, false);
        assert_eq!(check(&r, "listen").status, Status::Warn, "{}", r.render());
        assert!(!r.failed());
    }

    #[test]
    fn the_report_names_the_fix_under_each_problem_and_counts() {
        let f = Fixture::new();
        f.write_config("");
        let text = f.run(NOW + 60, false).render();
        assert!(text.contains("FAIL  bootstrap"), "{text}");
        assert!(
            text.contains("fix: add the coordinator's address"),
            "{text}"
        );
        assert!(text.contains("1 failed"), "{text}");
        let json = serde_json::to_value(f.run(NOW + 60, false)).unwrap();
        assert_eq!(json["kind"], "worker");
        assert!(
            json["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["status"] == "fail")
        );
    }
}

//! `cybermesh demo init`: generates a complete local network (keys, governance root, signed
//! manifest, trust root, configs) for the demonstration. Generated keys are for local
//! demonstrations only.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Subcommand;
use cybermesh_crypto::{Envelope, SecretKey, canonical};
use cybermesh_intelligence::TrustRoot;
use cybermesh_protocol::{
    GovernanceRoot, KeySet, Member, Operator, OperatorId, PROTOCOL_VERSION, Role, SignerEntry,
    TrustManifest, payload_type,
};

use crate::util::{self, write, write_json};

#[derive(Subcommand, Debug)]
pub enum DemoCmd {
    /// Generate keys, manifest and configs for a local demonstration network.
    Init {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        domains: PathBuf,
        #[arg(long, value_parser = ["local", "docker"], default_value = "local")]
        mode: String,
        /// Enrol a simulated compromised operator running this adversary mode.
        #[arg(long)]
        adversary: Option<String>,
        #[arg(long, default_value_t = 4100)]
        base_port: u16,
        #[arg(long, default_value = "cybermesh-demo")]
        network_id: String,
        /// Enable CT monitoring of this pinned log (workers opt in, coordinator schedules).
        #[arg(long)]
        ct_log: Option<String>,
        #[arg(long, default_value_t = 8)]
        ct_tiles: u64,
    },
}

struct Org {
    id: &'static str,
    name: &'static str,
    workers: &'static [&'static str],
    release_key: bool,
}

const ORGS: &[Org] = &[
    Org {
        id: "org-a",
        name: "Organisation A (coordinator host)",
        workers: &["a1"],
        release_key: true,
    },
    Org {
        id: "org-b",
        name: "Organisation B",
        workers: &["b1", "b2"],
        release_key: true,
    },
    Org {
        id: "org-c",
        name: "Organisation C",
        workers: &["c1"],
        release_key: true,
    },
    Org {
        id: "org-d",
        name: "Organisation D",
        workers: &["d1"],
        release_key: false,
    },
];

fn key(out: &Path, name: &str) -> Result<SecretKey> {
    let p = out.join("keys").join(format!("{name}.key.json"));
    let k = SecretKey::generate()?;
    k.write_to_file(&p)?;
    Ok(k)
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        if e.file_type()?.is_file() {
            std::fs::copy(e.path(), to.join(e.file_name()))?;
        }
    }
    Ok(())
}

pub fn run(c: DemoCmd) -> Result<()> {
    let DemoCmd::Init {
        out,
        evidence,
        domains,
        mode,
        adversary,
        base_port,
        network_id,
        ct_log,
        ct_tiles,
    } = c;
    if out.join("manifest.json").exists() {
        bail!(
            "{} already contains a demo network; remove it first",
            out.display()
        );
    }
    std::fs::create_dir_all(out.join("keys"))?;
    std::fs::create_dir_all(out.join("public"))?;
    copy_dir(&evidence, &out.join("evidence"))?;
    std::fs::copy(&domains, out.join("domains.txt"))?;
    let now = util::now();

    let gov: Vec<SecretKey> = (1..=3)
        .map(|i| key(&out, &format!("gov-{i}")))
        .collect::<Result<_>>()?;
    let root = GovernanceRoot {
        network_id: network_id.clone(),
        threshold: 2,
        keys: gov.iter().map(SecretKey::public_key).collect(),
    };
    let coord = key(&out, "coordinator")?;

    let mut operators = Vec::new();
    let mut members = vec![];
    let mut signers = vec![];
    let mut workers: Vec<(String, String)> = vec![];
    let mut all_orgs: Vec<(&str, &str, Vec<&str>, bool)> = ORGS
        .iter()
        .map(|o| (o.id, o.name, o.workers.to_vec(), o.release_key))
        .collect();
    if adversary.is_some() {
        all_orgs.push((
            "org-m",
            "Organisation M (simulated compromised)",
            vec!["m1"],
            false,
        ));
    }
    for (id, name, ws, release) in &all_orgs {
        let op = OperatorId::new(id)?;
        operators.push(Operator {
            id: op.clone(),
            name: (*name).to_owned(),
        });
        if *id == "org-a" {
            members.push(Member {
                label: "coordinator".into(),
                operator: op.clone(),
                public_key: coord.public_key(),
                roles: vec![Role::Issuer, Role::Verifier],
            });
        }
        for w in ws {
            let k = key(&out, &format!("worker-{w}"))?;
            members.push(Member {
                label: format!("worker-{w}"),
                operator: op.clone(),
                public_key: k.public_key(),
                roles: vec![Role::Worker],
            });
            workers.push(((*w).to_owned(), (*id).to_owned()));
        }
        if *release {
            let k = key(&out, &format!("release-{id}"))?;
            signers.push(SignerEntry {
                label: format!("release-{id}"),
                operator: op.clone(),
                public_key: k.public_key(),
            });
        }
    }
    let manifest = TrustManifest {
        v: PROTOCOL_VERSION,
        network_id: network_id.clone(),
        sequence: 1,
        issued_at: now,
        expires_at: now + 180 * 86_400,
        operators,
        members,
        release_signers: KeySet {
            threshold: 2,
            keys: signers,
        },
        revocations: vec![],
    };
    manifest.validate()?;
    write_json(&out.join("manifest.unsigned.json"), &manifest)?;
    let bytes = canonical::to_vec(&manifest)?;
    let mut env = Envelope::sign(payload_type::MANIFEST, &bytes, &gov[0]);
    env.add_signature(&gov[1])?;
    write(&out.join("manifest.json"), &env.to_vec()?)?;
    write_json(&out.join("governance-root.json"), &root)?;
    write_json(
        &out.join("trust-root.json"),
        &TrustRoot::from_manifest(&manifest),
    )?;
    write_json(
        &out.join("public").join("trust-root.json"),
        &TrustRoot::from_manifest(&manifest),
    )?;

    let coord_peer = cybermesh_network::peer_id_of(&coord.public_key())?;
    let (coord_listen, coord_addr) = if mode == "docker" {
        (
            "/ip4/0.0.0.0/tcp/4100".to_owned(),
            format!("/ip4/172.28.0.10/tcp/4100/p2p/{coord_peer}"),
        )
    } else {
        (
            format!("/ip4/127.0.0.1/tcp/{base_port}"),
            format!("/ip4/127.0.0.1/tcp/{base_port}/p2p/{coord_peer}"),
        )
    };
    let ct_section = match &ct_log {
        Some(id) => format!(
            "\n# Certificate Transparency monitoring (findings are advisory warnings only).\n[ct]\nlog_id = \"{id}\"\nfirst_tile = 0\ntile_count = {ct_tiles}\ntiles_per_task = 2\nreplication = 2\n"
        ),
        None => String::new(),
    };
    let coord_toml = format!(
        r#"# CyberMesh coordinator (issuer + verifier) for organisation org-a.
network_id = "{network_id}"
issuer_key = "keys/coordinator.key.json"
verifier_key = "keys/coordinator.key.json"
manifest = "manifest.json"
governance_root = "governance-root.json"
evidence_dir = "evidence"
state_dir = "state/coordinator"
listen = ["{coord_listen}"]
domains_file = "domains.txt"
batch_size = 8
replication = 3
task_ttl_secs = 300
result_timeout_secs = 15
max_attempts = 3
liveness_secs = 45
max_inflight = 4
exit_when_done = true

[policy]
min_operators = 3
result_grace_secs = 60
warn_min_score_bp = 4000
block_min_score_bp = 7000
{ct_section}"#
    );
    write(&out.join("coordinator.toml"), coord_toml.as_bytes())?;

    for (i, (w, org)) in workers.iter().enumerate() {
        let listen = if mode == "docker" {
            "/ip4/0.0.0.0/tcp/4100".to_owned()
        } else {
            format!("/ip4/127.0.0.1/tcp/{}", base_port + 1 + u16::try_from(i)?)
        };
        let ct_on = ct_log.is_some();
        let adv = if *org == "org-m" {
            format!(
                "adversary = \"{}\"\n",
                adversary.as_deref().unwrap_or("flip-verdicts")
            )
        } else {
            String::new()
        };
        let toml = format!(
            r#"# CyberMesh worker {w} for operator {org}. Opt-in, resource-limited, no inbound task code.
network_id = "{network_id}"
key = "keys/worker-{w}.key.json"
manifest = "manifest.json"
governance_root = "governance-root.json"
evidence_dir = "evidence"
state_dir = "state/{w}"
control_dir = "state/{w}/control"
listen = ["{listen}"]
bootstrap = ["{coord_addr}"]
heartbeat_secs = 5
{adv}
[resources]
cpu_percent = 1.0
cpu_window_secs = 60
memory_mb = 200
max_load_per_cpu = 4.0
outbound_kib_per_sec = 64
max_queue = 16
active_hours_utc = ["00:00-24:00"]
ct_scanning = {ct_on}
"#
        );
        write(&out.join(format!("worker-{w}.toml")), toml.as_bytes())?;
    }
    println!(
        "demo network written to {} ({} operators, {} workers, mode={mode})",
        out.display(),
        all_orgs.len(),
        workers.len()
    );
    Ok(())
}

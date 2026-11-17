//! `cybermesh` command-line interface.

#![forbid(unsafe_code)]

mod anchor_cmd;
mod ct_cmd;
mod demo;
#[cfg(feature = "dev-tools")]
mod dev;
mod eval;
mod keys;
mod release_cmd;
mod serve;
mod util;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use cybermesh_protocol::SystemClock;

#[derive(Parser, Debug)]
#[command(
    name = "cybermesh",
    version,
    about = "CyberMesh: community-verified phishing and malicious-domain intelligence"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate an Ed25519 key file (0600).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Show the public key, key id and libp2p peer id of a key file.
    KeyInfo {
        #[arg(long)]
        key: PathBuf,
    },
    /// Governance: trust root and manifest management.
    #[command(subcommand)]
    Governance(keys::GovernanceCmd),
    /// Evidence bundles (pinned snapshots).
    #[command(subcommand)]
    Evidence(keys::EvidenceCmd),
    /// Assess domains locally with the deterministic engine (no network access).
    Analyze {
        #[arg(long)]
        evidence: PathBuf,
        domains: Vec<String>,
    },
    /// Worker node.
    #[command(subcommand)]
    Worker(WorkerCmd),
    /// Coordinator (task issuer + result verifier).
    #[command(subcommand)]
    Coordinator(CoordinatorCmd),
    /// Independent verifier run by another organisation (verifies and signs its own records).
    #[command(subcommand)]
    Verifier(VerifierCmd),
    /// Threat-intelligence releases.
    #[command(subcommand)]
    Release(release_cmd::ReleaseCmd),
    /// False-positive appeals.
    #[command(subcommand)]
    Appeal(release_cmd::AppealCmd),
    /// Transparency log and optional anchoring.
    #[command(subcommand)]
    Anchor(anchor_cmd::AnchorCmd),
    /// Certificate Transparency monitoring.
    #[command(subcommand)]
    Ct(ct_cmd::CtCmd),
    /// Serve a directory (releases) and the local phishing test page.
    Serve {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8088")]
        addr: String,
        /// Allow binding a non-loopback address.
        #[arg(long)]
        public: bool,
    },
    /// Local demonstration helpers.
    #[command(subcommand)]
    Demo(demo::DemoCmd),
    /// Measure protection quality on a labelled dataset.
    Eval(eval::EvalArgs),
    /// Measure engine throughput.
    Bench {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long, default_value_t = 100_000)]
        n: usize,
    },
    /// Developer utilities (build with `--features dev-tools`).
    #[cfg(feature = "dev-tools")]
    #[command(subcommand)]
    Dev(dev::DevCmd),
}

#[derive(Subcommand, Debug)]
enum WorkerCmd {
    /// Run a worker.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Show the worker's live status file.
    Status {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Pause task execution (the worker stays connected).
    Pause {
        #[arg(long)]
        control_dir: PathBuf,
    },
    /// Resume after `pause`.
    Resume {
        #[arg(long)]
        control_dir: PathBuf,
    },
    /// Stop the worker process.
    Stop {
        #[arg(long)]
        control_dir: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum VerifierCmd {
    /// Run an independent verifier.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum CoordinatorCmd {
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,libp2p=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn shutdown_signal() -> tokio::sync::watch::Receiver<bool> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = term.recv() => {}
                }
            } else {
                let _ = ctrl_c.await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        let _ = tx.send(true);
    });
    rx
}

fn control_file(dir: &std::path::Path, name: &str, create: bool) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let p = dir.join(name);
    if create {
        std::fs::write(&p, b"")?;
    } else if p.exists() {
        std::fs::remove_file(&p)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let clock = Arc::new(SystemClock);
    match cli.cmd {
        Cmd::Keygen { out } => keys::keygen(&out),
        Cmd::KeyInfo { key } => keys::key_info(&key),
        Cmd::Governance(c) => keys::governance(c),
        Cmd::Evidence(c) => keys::evidence(c),
        Cmd::Analyze { evidence, domains } => eval::analyze(&evidence, &domains),
        Cmd::Worker(WorkerCmd::Run { config }) => {
            let cfg = cybermesh_node::config::WorkerConfig::load(&config)?;
            let setup = cybermesh_node::worker::setup_from_config(&cfg, clock)?;
            let status = cybermesh_node::worker::run_worker(setup, shutdown_signal().await).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Cmd::Worker(WorkerCmd::Status { state_dir }) => {
            let p = state_dir.join("status.json");
            let s =
                std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
            println!("{s}");
            Ok(())
        }
        Cmd::Worker(WorkerCmd::Pause { control_dir }) => control_file(&control_dir, "PAUSE", true),
        Cmd::Worker(WorkerCmd::Resume { control_dir }) => {
            control_file(&control_dir, "PAUSE", false)
        }
        Cmd::Worker(WorkerCmd::Stop { control_dir }) => control_file(&control_dir, "STOP", true),
        Cmd::Coordinator(CoordinatorCmd::Run { config }) => {
            let cfg = cybermesh_node::config::CoordinatorConfig::load(&config)?;
            let (setup, skipped) = cybermesh_node::coordinator::setup_from_config(&cfg, clock)?;
            if skipped > 0 {
                tracing::warn!(
                    skipped,
                    "input lines were not valid domains and were skipped"
                );
            }
            let report =
                cybermesh_node::coordinator::run_coordinator(setup, shutdown_signal().await)
                    .await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Cmd::Verifier(VerifierCmd::Run { config }) => {
            let cfg = cybermesh_node::config::VerifierConfig::load(&config)?;
            let setup = cybermesh_node::verifier::setup_from_config(&cfg, clock)?;
            let report =
                cybermesh_node::verifier::run_verifier(setup, shutdown_signal().await).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Cmd::Release(c) => release_cmd::run(c),
        Cmd::Appeal(c) => release_cmd::appeal(c),
        Cmd::Anchor(c) => anchor_cmd::run(c),
        Cmd::Ct(c) => ct_cmd::run(c),
        Cmd::Serve { dir, addr, public } => serve::serve(&dir, &addr, public),
        Cmd::Demo(c) => demo::run(c),
        Cmd::Eval(a) => eval::eval(&a),
        Cmd::Bench { evidence, n } => eval::bench(&evidence, n),
        #[cfg(feature = "dev-tools")]
        Cmd::Dev(c) => dev::run(c),
    }
}

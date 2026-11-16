use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use clap::Subcommand;
use cybermesh_anchor::ots::DetachedTimestamp;
use cybermesh_anchor::{
    Anchor, AnchorReceipt, AnchorStatus, Checkpoint, InclusionProof, LocalChain, LogEntry,
    TransparencyLog,
};
use cybermesh_crypto::{Digest, Envelope, canonical};
use cybermesh_intelligence::ThreatRelease;
use serde::{Deserialize, Serialize};

use crate::util::{self, read, read_json, write_json};

/// A checkpoint and the receipt proving it was anchored.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredCheckpoint {
    pub checkpoint: Checkpoint,
    pub commitment: Digest,
    pub receipt: AnchorReceipt,
}

#[derive(Subcommand, Debug)]
pub enum AnchorCmd {
    /// Append a signed release to the transparency log.
    Append {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        log_id: String,
        #[arg(long)]
        release: PathBuf,
    },
    /// Commit the current log checkpoint to an anchor. Failure never affects releases.
    Commit {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        log_id: String,
        #[arg(long, value_parser = ["local", "ots"], default_value = "local")]
        adapter: String,
        /// Local test chain file (adapter=local).
        #[arg(long)]
        chain: Option<PathBuf>,
        /// Calendar URLs (adapter=ots). Defaults to the public OpenTimestamps calendars.
        #[arg(long = "calendar")]
        calendars: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Produce an inclusion proof for a release against an anchored checkpoint size.
    Prove {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        log_id: String,
        #[arg(long)]
        release: PathBuf,
        /// Checkpoint size (defaults to the current log size).
        #[arg(long)]
        size: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify offline: release -> inclusion proof -> checkpoint -> anchor receipt.
    Verify {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        release: Option<PathBuf>,
        /// Local chain file to check the block against (adapter=local).
        #[arg(long)]
        chain: Option<PathBuf>,
    },
}

fn release_entry(path: &std::path::Path) -> Result<LogEntry> {
    let env = Envelope::parse(&read(path)?, cybermesh_intelligence::MAX_RELEASE_BYTES)?;
    let payload = env.payload_bytes()?;
    let r: ThreatRelease = canonical::from_slice(&payload)?;
    Ok(LogEntry {
        sequence: r.sequence,
        release_digest: Digest::of(&payload),
    })
}

pub fn run(c: AnchorCmd) -> Result<()> {
    match c {
        AnchorCmd::Append {
            log,
            log_id,
            release,
        } => {
            let mut l = TransparencyLog::load_or_create(&log, &log_id)?;
            let idx = l.append(release_entry(&release)?)?;
            l.save(&log)?;
            let cp = l.checkpoint()?;
            println!(
                "appended at index {idx}; checkpoint size={} root={}",
                cp.size, cp.root
            );
            Ok(())
        }
        AnchorCmd::Commit {
            log,
            log_id,
            adapter,
            chain,
            calendars,
            out,
        } => {
            let l = TransparencyLog::load_or_create(&log, &log_id)?;
            let cp = l.checkpoint()?;
            if cp.size == 0 {
                bail!("log is empty");
            }
            let commitment = cp.commitment();
            let result = match adapter.as_str() {
                "local" => {
                    let chain = chain.context("--chain is required for the local adapter")?;
                    LocalChain::open(&chain, &format!("{log_id}-localchain"))?
                        .submit(commitment, util::now())
                }
                "ots" => submit_ots(commitment, calendars),
                _ => bail!("unknown adapter"),
            };
            match result {
                Ok(receipt) => {
                    write_json(
                        &out,
                        &AnchoredCheckpoint {
                            checkpoint: cp.clone(),
                            commitment,
                            receipt,
                        },
                    )?;
                    println!(
                        "anchored checkpoint size={} commitment={commitment}",
                        cp.size
                    );
                    Ok(())
                }
                Err(e) => {
                    // Anchoring is off the protection path: report and let the operator retry.
                    eprintln!("anchor unavailable ({e}); releases remain valid; retry later");
                    std::process::exit(3);
                }
            }
        }
        AnchorCmd::Prove {
            log,
            log_id,
            release,
            size,
            out,
        } => {
            let l = TransparencyLog::load_or_create(&log, &log_id)?;
            let entry = release_entry(&release)?;
            let idx = l
                .find(&entry.release_digest)
                .context("release is not in the log")?;
            let size = size.unwrap_or(l.entries.len() as u64);
            write_json(&out, &l.prove_inclusion(idx, size)?)
        }
        AnchorCmd::Verify {
            proof,
            receipt,
            release,
            chain,
        } => {
            let p: InclusionProof = read_json(&proof)?;
            let a: AnchoredCheckpoint = read_json(&receipt)?;
            if !p.verify() {
                bail!("inclusion proof does not verify");
            }
            if p.checkpoint != a.checkpoint {
                bail!("proof and receipt refer to different checkpoints");
            }
            if a.commitment != a.checkpoint.commitment() {
                bail!("receipt commitment does not match its checkpoint");
            }
            if let Some(r) = release {
                let e = release_entry(&r)?;
                if e != p.entry {
                    bail!("release does not match the proven log entry");
                }
            }
            let statuses = match &a.receipt {
                AnchorReceipt::LocalChain(r) => {
                    let ch = match &chain {
                        Some(c) => Some(LocalChain::open(c, &r.chain_id)?),
                        None => None,
                    };
                    vec![LocalChain::verify_receipt(r, &a.commitment, ch.as_ref())?]
                }
                AnchorReceipt::OpenTimestamps { ots, .. } => {
                    let bytes = base64::engine::general_purpose::STANDARD.decode(ots)?;
                    DetachedTimestamp::parse(&bytes)?.verify(&a.commitment.0)?
                }
            };
            println!(
                "OK release seq={} included in checkpoint size={} root={}",
                p.entry.sequence, p.checkpoint.size, p.checkpoint.root
            );
            for s in statuses {
                match s {
                    AnchorStatus::LocalChainConfirmed { chain_id, height } => {
                        println!("  anchored: local test chain {chain_id} block {height}");
                    }
                    AnchorStatus::Pending { calendar } => println!("  pending: {calendar}"),
                    AnchorStatus::BitcoinAttested {
                        height,
                        merkle_root_display,
                    } => println!(
                        "  bitcoin: block {height} must have merkleroot {merkle_root_display} (check with your own node)"
                    ),
                    AnchorStatus::Unverifiable { reason } => {
                        println!("  unverifiable branch: {reason}")
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "ots")]
fn submit_ots(
    commitment: Digest,
    calendars: Vec<String>,
) -> Result<AnchorReceipt, cybermesh_anchor::AnchorError> {
    let mut a = cybermesh_anchor::ots::OtsAnchor::default();
    if !calendars.is_empty() {
        a.calendars = calendars;
    }
    a.submit(commitment, util::now())
}

#[cfg(not(feature = "ots"))]
fn submit_ots(
    _commitment: Digest,
    _calendars: Vec<String>,
) -> Result<AnchorReceipt, cybermesh_anchor::AnchorError> {
    Err(cybermesh_anchor::AnchorError::Unsupported(
        "built without the ots feature".into(),
    ))
}

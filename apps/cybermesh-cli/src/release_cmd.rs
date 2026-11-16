use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use clap::Subcommand;
use cybermesh_crypto::{Digest, Envelope, SecretKey, canonical};
use cybermesh_intelligence::{
    BuildParams, ConsumerState, ReleaseRef, ThreatRelease, TrustRoot, build_release, rollback,
    verify_release,
};
use cybermesh_protocol::{
    AppealDecision, AppealOutcome, GovernanceRoot, PROTOCOL_VERSION, Role, TrustManifest,
    payload_type,
};
use cybermesh_verifier::VerificationRecord;

use crate::util::{self, read, read_json, write, write_json};

#[derive(Subcommand, Debug)]
pub enum ReleaseCmd {
    /// Deterministically build an unsigned release payload from verification records.
    Build {
        #[arg(long)]
        records: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        root: PathBuf,
        /// Directory of governance-signed appeal decisions.
        #[arg(long)]
        decisions: Option<PathBuf>,
        #[arg(long)]
        sequence: u64,
        /// Issue time (Unix seconds). Fixed explicitly so co-signers get identical bytes.
        #[arg(long)]
        issued_at: u64,
        #[arg(long, default_value_t = 7 * 86_400)]
        ttl_secs: u64,
        #[arg(long, default_value_t = 30 * 86_400)]
        max_record_age_secs: u64,
        /// Previous signed release (hash chain).
        #[arg(long)]
        previous: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a payload (or co-sign by merging into an existing signed release).
    Sign {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        merge: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a signed release offline.
    Verify {
        #[arg(long)]
        release: PathBuf,
        /// Trust root JSON (release signers + threshold).
        #[arg(long)]
        trust_root: PathBuf,
        /// Anti-rollback state file (read, and updated on success with --update-state).
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        update_state: bool,
        #[arg(long)]
        now: Option<u64>,
    },
    /// Derive the consumer trust root from a verified manifest.
    TrustRoot {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Republish an older release's content under a new sequence.
    Rollback {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        /// Governance root, required with --decisions (decision signatures are verified).
        #[arg(long)]
        governance_root: Option<PathBuf>,
        #[arg(long, requires = "governance_root")]
        decisions: Option<PathBuf>,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        issued_at: u64,
        #[arg(long, default_value_t = 7 * 86_400)]
        ttl_secs: u64,
        #[arg(long)]
        previous: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print a release's entries.
    Show {
        #[arg(long)]
        release: PathBuf,
    },
}

/// Loads verifier-signed records, checking each signature against the manifest.
pub fn load_records(dir: &Path, m: &TrustManifest) -> Result<Vec<(Digest, VerificationRecord)>> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    entries.sort();
    for p in entries {
        let env = Envelope::parse(&read(&p)?, 16 << 20)?;
        let v = env
            .verify(payload_type::VERIFICATION, 1, |id| {
                m.key_with_role(id, Role::Verifier)
            })
            .with_context(|| format!("{}: not signed by an enrolled verifier", p.display()))?;
        let rec: VerificationRecord = canonical::from_slice(&v.payload)?;
        out.push((Digest::of(&v.payload), rec));
    }
    Ok(out)
}

fn load_decisions(dir: Option<&Path>, root: &GovernanceRoot) -> Result<Vec<AppealDecision>> {
    let Some(dir) = dir else { return Ok(vec![]) };
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let env = Envelope::parse(&read(&p)?, 1 << 20)?;
        let payload = root.verify_envelope(&env, payload_type::APPEAL_DECISION)?;
        let d: AppealDecision = canonical::from_slice(&payload)?;
        out.push(d);
    }
    Ok(out)
}

fn release_ref(path: &Path) -> Result<ReleaseRef> {
    let env = Envelope::parse(&read(path)?, cybermesh_intelligence::MAX_RELEASE_BYTES)?;
    let payload = env.payload_bytes()?;
    let r: ThreatRelease = canonical::from_slice(&payload)?;
    Ok(ReleaseRef {
        sequence: r.sequence,
        digest: Digest::of(&payload),
    })
}

pub fn run(c: ReleaseCmd) -> Result<()> {
    match c {
        ReleaseCmd::Build {
            records,
            manifest,
            root,
            decisions,
            sequence,
            issued_at,
            ttl_secs,
            max_record_age_secs,
            previous,
            out,
        } => {
            let m = util::load_manifest(&manifest, &root, issued_at)?;
            let groot: GovernanceRoot = read_json(&root)?;
            let recs = load_records(&records, &m)?;
            let decs = load_decisions(decisions.as_deref(), &groot)?;
            let prev = previous.as_deref().map(release_ref).transpose()?;
            if let Some(p) = &prev
                && p.sequence >= sequence
            {
                bail!("sequence must be greater than the previous release's sequence");
            }
            let rel = build_release(
                &recs,
                &decs,
                &BuildParams {
                    network_id: m.network_id.clone(),
                    sequence,
                    previous: prev,
                    issued_at,
                    ttl_secs,
                    max_record_age_secs,
                },
            )?;
            let bytes = canonical::to_vec(&rel)?;
            write(&out, &bytes)?;
            eprintln!(
                "release {} built: {} entries ({} block, {} warn), {} corrections, payload {}",
                rel.sequence,
                rel.entries.len(),
                rel.entries
                    .iter()
                    .filter(|e| e.action == cybermesh_intelligence::Action::Block)
                    .count(),
                rel.entries
                    .iter()
                    .filter(|e| e.action == cybermesh_intelligence::Action::Warn)
                    .count(),
                rel.corrections.len(),
                Digest::of(&bytes)
            );
            Ok(())
        }
        ReleaseCmd::Sign {
            payload,
            key,
            merge,
            out,
        } => {
            let bytes = read(&payload)?;
            let _: ThreatRelease =
                canonical::from_slice(&bytes).context("payload is not a canonical release")?;
            let k = SecretKey::read_from_file(&key)?;
            let env = match merge {
                Some(p) => {
                    let mut e =
                        Envelope::parse(&read(&p)?, cybermesh_intelligence::MAX_RELEASE_BYTES)?;
                    if e.payload_bytes()? != bytes {
                        bail!(
                            "refusing to co-sign: the existing envelope carries different payload bytes"
                        );
                    }
                    e.add_signature(&k)?;
                    e
                }
                None => Envelope::sign(payload_type::RELEASE, &bytes, &k),
            };
            write(&out, &env.to_vec()?)?;
            eprintln!(
                "signed by {} ({} signature(s))",
                k.key_id().short(),
                env.signatures.len()
            );
            Ok(())
        }
        ReleaseCmd::Verify {
            release,
            trust_root,
            state,
            update_state,
            now,
        } => {
            let root: TrustRoot = read_json(&trust_root)?;
            let st: Option<ConsumerState> = match &state {
                Some(p) if p.exists() => Some(read_json(p)?),
                _ => None,
            };
            let v = verify_release(
                &read(&release)?,
                &root,
                now.unwrap_or_else(util::now),
                st.as_ref(),
            )?;
            println!(
                "OK release sequence={} entries={} corrections={} expires_at={} signed_by_operators=[{}] digest={}",
                v.release.sequence,
                v.release.entries.len(),
                v.release.corrections.len(),
                v.release.expires_at,
                v.operators
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                v.digest
            );
            if update_state && let Some(p) = state {
                write_json(
                    &p,
                    &ConsumerState {
                        sequence: v.release.sequence,
                        digest: v.digest,
                    },
                )?;
            }
            Ok(())
        }
        ReleaseCmd::TrustRoot {
            manifest,
            root,
            out,
        } => {
            let m = util::load_manifest(&manifest, &root, util::now())?;
            write_json(&out, &TrustRoot::from_manifest(&m))
        }
        ReleaseCmd::Rollback {
            target,
            trust_root,
            governance_root,
            decisions,
            sequence,
            issued_at,
            ttl_secs,
            previous,
            out,
        } => {
            let root: TrustRoot = read_json(&trust_root)?;
            // The target must have been a validly signed release (expiry not required).
            let env = Envelope::parse(&read(&target)?, cybermesh_intelligence::MAX_RELEASE_BYTES)?;
            let payload = env.payload_bytes()?;
            let t: ThreatRelease = canonical::from_slice(&payload)?;
            verify_release(&read(&target)?, &root, t.issued_at, None)
                .context("rollback target is not a validly signed release")?;
            let decs = match (&decisions, &governance_root) {
                (Some(d), Some(g)) => load_decisions(Some(d), &read_json::<GovernanceRoot>(g)?)?,
                _ => vec![],
            };
            let rel = rollback(
                &t,
                &decs,
                &cybermesh_intelligence::BuildParams {
                    network_id: t.network_id.clone(),
                    sequence,
                    previous: Some(release_ref(&previous)?),
                    issued_at,
                    ttl_secs,
                    max_record_age_secs: 0,
                },
            )?;
            write(&out, &canonical::to_vec(&rel)?)
        }
        ReleaseCmd::Show { release } => {
            let env = Envelope::parse(&read(&release)?, cybermesh_intelligence::MAX_RELEASE_BYTES)?;
            let r: ThreatRelease = canonical::from_slice(&env.payload_bytes()?)?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(())
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum AppealCmd {
    /// Record a governance decision on a false-positive appeal (signed by governance keys).
    Decide {
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        appeal_id: String,
        #[arg(long)]
        indicator: String,
        #[arg(long, value_parser = ["upheld", "rejected"])]
        outcome: String,
        #[arg(long)]
        rationale: String,
        #[arg(long)]
        decided_at: Option<u64>,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

pub fn appeal(c: AppealCmd) -> Result<()> {
    match c {
        AppealCmd::Decide {
            network_id,
            appeal_id,
            indicator,
            outcome,
            rationale,
            decided_at,
            keys,
            out,
        } => {
            let indicator = cybermesh_analysis::normalize_domain(&indicator)?;
            let printable = |s: &str| s.bytes().all(|b| (0x20..0x7f).contains(&b));
            if rationale.len() > 500 || appeal_id.is_empty() || appeal_id.len() > 64 {
                bail!("rationale must be <= 500 bytes and appeal id 1..=64 bytes");
            }
            if !printable(&rationale) || !printable(&appeal_id) {
                bail!(
                    "appeal id and rationale must be printable ASCII (they are published in releases)"
                );
            }
            let d = AppealDecision {
                v: PROTOCOL_VERSION,
                network_id,
                appeal_id,
                indicator,
                outcome: if outcome == "upheld" {
                    AppealOutcome::Upheld
                } else {
                    AppealOutcome::Rejected
                },
                rationale,
                decided_at: decided_at.unwrap_or_else(util::now),
            };
            let bytes = canonical::to_vec(&d)?;
            let mut env: Option<Envelope> = None;
            for kp in keys {
                let k = SecretKey::read_from_file(&kp)?;
                match &mut env {
                    None => env = Some(Envelope::sign(payload_type::APPEAL_DECISION, &bytes, &k)),
                    Some(e) => e.add_signature(&k)?,
                }
            }
            let env = env.ok_or_else(|| anyhow::anyhow!("no keys"))?;
            write(&out, &env.to_vec()?)
        }
    }
}

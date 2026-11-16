use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Subcommand;
use cybermesh_analysis::{BundleManifest, EvidenceBundle};
use cybermesh_crypto::{Digest, Envelope, PublicKey, SecretKey, canonical};
use cybermesh_protocol::{GovernanceRoot, TrustManifest, payload_type};

use crate::util::{self, read, read_json, write, write_json};

pub fn keygen(out: &Path) -> Result<()> {
    if let Some(d) = out.parent()
        && !d.as_os_str().is_empty()
    {
        std::fs::create_dir_all(d)?;
    }
    let k = SecretKey::generate()?;
    k.write_to_file(out)?;
    println!("{}", k.public_key());
    Ok(())
}

pub fn key_info(path: &Path) -> Result<()> {
    let k = SecretKey::read_from_file(path)?;
    let peer = cybermesh_network::peer_id_of(&k.public_key())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "public_key": k.public_key().to_hex(),
            "key_id": k.key_id().to_string(),
            "peer_id": peer.to_string(),
        }))?
    );
    Ok(())
}

#[derive(Subcommand, Debug)]
pub enum GovernanceCmd {
    /// Create a governance root (pinned trust anchor) from public keys.
    InitRoot {
        #[arg(long)]
        network_id: String,
        #[arg(long)]
        threshold: u8,
        /// Hex public keys of governance members.
        #[arg(long = "public-key", required = true)]
        public_keys: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign (or co-sign) an unsigned manifest JSON file.
    SignManifest {
        /// Unsigned TrustManifest JSON.
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        /// Existing signed manifest to add signatures to.
        #[arg(long)]
        merge: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a signed manifest against a governance root.
    VerifyManifest {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        root: PathBuf,
    },
}

pub fn governance(c: GovernanceCmd) -> Result<()> {
    match c {
        GovernanceCmd::InitRoot {
            network_id,
            threshold,
            public_keys,
            out,
        } => {
            let keys = public_keys
                .iter()
                .map(|k| PublicKey::from_hex(k))
                .collect::<Result<Vec<_>, _>>()?;
            if threshold == 0 || usize::from(threshold) > keys.len() {
                bail!("threshold must be between 1 and the number of keys");
            }
            write_json(
                &out,
                &GovernanceRoot {
                    network_id,
                    threshold,
                    keys,
                },
            )
        }
        GovernanceCmd::SignManifest {
            manifest,
            keys,
            merge,
            out,
        } => {
            let m: TrustManifest = read_json(&manifest)?;
            m.validate()?;
            let bytes = canonical::to_vec(&m)?;
            let mut env: Option<Envelope> = match merge {
                Some(p) => Some(Envelope::parse(&read(&p)?, 32 << 20)?),
                None => None,
            };
            for kp in keys {
                let k = SecretKey::read_from_file(&kp)?;
                match &mut env {
                    None => env = Some(Envelope::sign(payload_type::MANIFEST, &bytes, &k)),
                    Some(e) => {
                        if e.payload_bytes()? != bytes {
                            bail!("--merge envelope carries a different manifest");
                        }
                        e.add_signature(&k)?;
                    }
                }
            }
            let env = env.ok_or_else(|| anyhow::anyhow!("no keys"))?;
            write(&out, &env.to_vec()?)
        }
        GovernanceCmd::VerifyManifest { manifest, root } => {
            let m = util::load_manifest(&manifest, &root, util::now())?;
            println!(
                "OK manifest network={} sequence={} operators={} members={} release_threshold={}/{}",
                m.network_id,
                m.sequence,
                m.operators.len(),
                m.members.len(),
                m.release_signers.threshold,
                m.release_signers.keys.len()
            );
            Ok(())
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum EvidenceCmd {
    /// Recompute digests in DIR/bundle.json from the files present.
    Pin {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Verify DIR/bundle.json digests and print pins.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
}

pub fn evidence(c: EvidenceCmd) -> Result<()> {
    match c {
        EvidenceCmd::Pin { dir } => {
            let p = dir.join("bundle.json");
            let mut m: BundleManifest = read_json(&p)?;
            for s in &mut m.sources {
                s.sha256 = Digest::of(&read(&dir.join(&s.file))?);
            }
            write_json(&p, &m)?;
            EvidenceBundle::load(&dir)?;
            println!("pinned {} sources", m.sources.len());
            Ok(())
        }
        EvidenceCmd::Verify { dir } => {
            let b = EvidenceBundle::load(&dir)?;
            for (id, d) in &b.pins {
                println!("{id} {d}");
            }
            println!(
                "blocklists={} popular={} brands={} skipped_lines={}",
                b.blocklists.iter().map(|(_, s)| s.len()).sum::<usize>(),
                b.popular.len(),
                b.brands.len(),
                b.skipped_lines
            );
            Ok(())
        }
    }
}

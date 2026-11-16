use std::fs;
use std::path::{Path, PathBuf};

use cybermesh_crypto::Digest;
use serde::{Deserialize, Serialize};

/// A transparency-log checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub log_id: String,
    pub size: u64,
    pub root: Digest,
}

impl Checkpoint {
    /// The only value ever sent to an anchor: a domain-separated hash of the checkpoint.
    #[must_use]
    pub fn commitment(&self) -> Digest {
        Digest::tagged(
            "cybermesh/anchor-checkpoint/v1",
            &[self.log_id.as_bytes(), &self.size.to_be_bytes(), self.root.as_bytes()],
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("anchor unavailable: {0}")]
    Unavailable(String),
    #[error("anchor timed out")]
    Timeout,
    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),
    #[error("log error: {0}")]
    Log(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Receipt for a submitted commitment, verifiable offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "adapter", rename_all = "kebab-case")]
pub enum AnchorReceipt {
    LocalChain(LocalChainReceipt),
    OpenTimestamps {
        /// Base64 of a standard `.ots` detached timestamp over the commitment.
        ots: String,
        calendars: Vec<String>,
    },
}

/// What offline verification of a receipt established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum AnchorStatus {
    /// Included in a block of the local test chain.
    LocalChainConfirmed { chain_id: String, height: u64 },
    /// Submitted to an OpenTimestamps calendar; not yet in Bitcoin.
    Pending { calendar: String },
    /// The proof commits to a Bitcoin block merkle root. The verifier must compare
    /// `merkle_root_display` with `merkleroot` from `bitcoin-cli getblockheader` for a block
    /// at `height` obtained from their own node.
    BitcoinAttested {
        height: u64,
        merkle_root_display: String,
    },
    /// A branch used an operation this verifier does not implement.
    Unverifiable { reason: String },
}

/// A pluggable timestamping backend.
pub trait Anchor: std::fmt::Debug {
    fn name(&self) -> &'static str;
    /// Submits a 32-byte commitment. `now` is used only for local record keeping.
    fn submit(&mut self, commitment: Digest, now: u64) -> Result<AnchorReceipt, AnchorError>;
}

// ---------------------------------------------------------------------------------------
// Local test chain
// ---------------------------------------------------------------------------------------

/// One block of the local test chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub height: u64,
    pub prev: Digest,
    pub time: u64,
    pub commitment: Digest,
}

impl Block {
    #[must_use]
    pub fn hash(&self, chain_id: &str) -> Digest {
        Digest::tagged(
            "cybermesh/localchain-block/v1",
            &[
                chain_id.as_bytes(),
                &self.height.to_be_bytes(),
                self.prev.as_bytes(),
                &self.time.to_be_bytes(),
                self.commitment.as_bytes(),
            ],
        )
    }
}

/// Receipt from the local test chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalChainReceipt {
    pub chain_id: String,
    pub block: Block,
    pub block_hash: Digest,
}

/// A hash-chained, append-only, single-writer block file. It reproduces the integrity
/// properties of a public chain (append-only, hash-linked, offline-verifiable receipts) for
/// tests and demonstrations. It provides no decentralisation and no third-party witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalChain {
    pub chain_id: String,
    pub blocks: Vec<Block>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl LocalChain {
    #[must_use]
    pub fn in_memory(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_owned(),
            blocks: Vec::new(),
            path: None,
        }
    }

    pub fn open(path: &Path, chain_id: &str) -> Result<Self, AnchorError> {
        let mut chain = if path.exists() {
            let bytes = fs::read(path).map_err(|e| AnchorError::Unavailable(e.to_string()))?;
            let c: LocalChain = serde_json::from_slice(&bytes)
                .map_err(|e| AnchorError::InvalidReceipt(e.to_string()))?;
            c.validate()?;
            if c.chain_id != chain_id {
                return Err(AnchorError::InvalidReceipt("chain id mismatch".into()));
            }
            c
        } else {
            Self::in_memory(chain_id)
        };
        chain.path = Some(path.to_owned());
        Ok(chain)
    }

    /// Checks every hash link.
    pub fn validate(&self) -> Result<(), AnchorError> {
        let mut prev = Digest([0u8; 32]);
        for (i, b) in self.blocks.iter().enumerate() {
            if b.height != i as u64 || b.prev != prev {
                return Err(AnchorError::InvalidReceipt(format!("broken link at height {i}")));
            }
            prev = b.hash(&self.chain_id);
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), AnchorError> {
        if let Some(p) = &self.path {
            let bytes = serde_json::to_vec_pretty(self)
                .map_err(|e| AnchorError::Unavailable(e.to_string()))?;
            crate::log::write_atomic(p, &bytes)
                .map_err(|e| AnchorError::Unavailable(e.to_string()))?;
        }
        Ok(())
    }

    /// Offline receipt verification. With `chain` supplied, also checks that the block is
    /// part of that (validated) chain, as a light client would check a block header.
    pub fn verify_receipt(
        receipt: &LocalChainReceipt,
        commitment: &Digest,
        chain: Option<&LocalChain>,
    ) -> Result<AnchorStatus, AnchorError> {
        if &receipt.block.commitment != commitment {
            return Err(AnchorError::InvalidReceipt("commitment mismatch".into()));
        }
        if receipt.block.hash(&receipt.chain_id) != receipt.block_hash {
            return Err(AnchorError::InvalidReceipt("block hash mismatch".into()));
        }
        if let Some(c) = chain {
            c.validate()?;
            let h = usize::try_from(receipt.block.height)
                .map_err(|_| AnchorError::InvalidReceipt("height".into()))?;
            match c.blocks.get(h) {
                Some(b) if c.chain_id == receipt.chain_id && b == &receipt.block => {}
                _ => return Err(AnchorError::InvalidReceipt("block not in chain".into())),
            }
        }
        Ok(AnchorStatus::LocalChainConfirmed {
            chain_id: receipt.chain_id.clone(),
            height: receipt.block.height,
        })
    }
}

impl Anchor for LocalChain {
    fn name(&self) -> &'static str {
        "local-chain"
    }

    fn submit(&mut self, commitment: Digest, now: u64) -> Result<AnchorReceipt, AnchorError> {
        let prev = self
            .blocks
            .last()
            .map_or(Digest([0u8; 32]), |b| b.hash(&self.chain_id));
        let block = Block {
            height: self.blocks.len() as u64,
            prev,
            time: now,
            commitment,
        };
        let block_hash = block.hash(&self.chain_id);
        self.blocks.push(block.clone());
        if let Err(e) = self.persist() {
            self.blocks.pop();
            return Err(e);
        }
        Ok(AnchorReceipt::LocalChain(LocalChainReceipt {
            chain_id: self.chain_id.clone(),
            block,
            block_hash,
        }))
    }
}

// ---------------------------------------------------------------------------------------
// Failure injection
// ---------------------------------------------------------------------------------------

/// Failure modes for adapter-failure tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    Unavailable,
    Timeout,
    /// Returns a receipt whose block hash does not match.
    CorruptReceipt,
}

/// An anchor that fails in a chosen way.
#[derive(Debug)]
pub struct FailingAnchor {
    pub mode: FailureMode,
    pub inner: LocalChain,
}

impl Anchor for FailingAnchor {
    fn name(&self) -> &'static str {
        "failing"
    }

    fn submit(&mut self, commitment: Digest, now: u64) -> Result<AnchorReceipt, AnchorError> {
        match self.mode {
            FailureMode::Unavailable => Err(AnchorError::Unavailable("injected outage".into())),
            FailureMode::Timeout => Err(AnchorError::Timeout),
            FailureMode::CorruptReceipt => {
                let mut r = self.inner.submit(commitment, now)?;
                if let AnchorReceipt::LocalChain(lc) = &mut r {
                    lc.block_hash = Digest::of(b"corrupted");
                }
                Ok(r)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_chain_receipts_verify_offline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.json");
        let mut chain = LocalChain::open(&path, "test-chain").unwrap();
        let c1 = Digest::of(b"c1");
        let c2 = Digest::of(b"c2");
        let AnchorReceipt::LocalChain(r1) = chain.submit(c1, 10).unwrap() else {
            panic!()
        };
        let AnchorReceipt::LocalChain(r2) = chain.submit(c2, 20).unwrap() else {
            panic!()
        };
        let reopened = LocalChain::open(&path, "test-chain").unwrap();
        assert_eq!(reopened.blocks.len(), 2);
        assert!(LocalChain::verify_receipt(&r1, &c1, Some(&reopened)).is_ok());
        assert!(LocalChain::verify_receipt(&r2, &c2, None).is_ok());
        assert!(LocalChain::verify_receipt(&r2, &c1, None).is_err());
        let mut forged = r2.clone();
        forged.block.time = 21;
        forged.block_hash = forged.block.hash("test-chain");
        assert!(LocalChain::verify_receipt(&forged, &c2, None).is_ok(), "self-consistent");
        assert!(
            LocalChain::verify_receipt(&forged, &c2, Some(&reopened)).is_err(),
            "but not in the chain"
        );
    }

    #[test]
    fn tampered_chain_file_is_detected() {
        let mut chain = LocalChain::in_memory("x");
        chain.submit(Digest::of(b"a"), 1).unwrap();
        chain.submit(Digest::of(b"b"), 2).unwrap();
        chain.blocks[0].commitment = Digest::of(b"rewritten");
        assert!(chain.validate().is_err());
    }

    #[test]
    fn injected_failures() {
        for mode in [FailureMode::Unavailable, FailureMode::Timeout] {
            let mut a = FailingAnchor {
                mode,
                inner: LocalChain::in_memory("f"),
            };
            assert!(a.submit(Digest::of(b"x"), 0).is_err());
        }
        let mut a = FailingAnchor {
            mode: FailureMode::CorruptReceipt,
            inner: LocalChain::in_memory("f"),
        };
        let AnchorReceipt::LocalChain(r) = a.submit(Digest::of(b"x"), 0).unwrap() else {
            panic!()
        };
        assert!(LocalChain::verify_receipt(&r, &Digest::of(b"x"), None).is_err());
    }
}

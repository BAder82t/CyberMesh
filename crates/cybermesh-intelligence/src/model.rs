use cybermesh_crypto::Digest;
use cybermesh_protocol::FindingCode;
use serde::{Deserialize, Serialize};

/// Reference to an earlier release (hash chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRef {
    pub sequence: u64,
    pub digest: Digest,
}

/// What a consumer should do on a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// High confidence, independently corroborated. Consumers may block automatically only
    /// when the user or administrator has opted in; otherwise they warn.
    Block,
    /// Advisory warning the user may dismiss.
    Warn,
}

/// Confidence class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    High,
    Medium,
}

/// Which hosts an entry matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchScope {
    /// The indicator host and any subdomain of it.
    HostAndSubdomains,
}

/// A human-readable reason for listing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub code: FindingCode,
    pub detail: String,
}

/// Kind of evidence backing an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// A signed verification record (task id + record digest).
    Verification,
    /// A pinned evidence snapshot (source id + snapshot digest).
    Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub id: String,
    pub digest: Digest,
}

/// One listed indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatEntry {
    /// Normalised host name.
    pub indicator: String,
    pub scope: MatchScope,
    pub action: Action,
    pub confidence: Confidence,
    pub risk_score_bp: u16,
    /// Number of distinct operators whose results agreed.
    pub operators: u8,
    pub reasons: Vec<Reason>,
    pub evidence: Vec<EvidenceRef>,
}

/// Why an indicator was removed or content changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorrectionKind {
    /// A false-positive appeal was upheld by governance.
    AppealUpheld,
    /// This release restores the content of an earlier sequence.
    Rollback,
}

/// A public correction record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub indicator: String,
    pub kind: CorrectionKind,
    pub reference: String,
    pub note: String,
}

/// A release payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatRelease {
    pub v: u16,
    pub network_id: String,
    pub sequence: u64,
    pub previous: Option<ReleaseRef>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub generator: String,
    /// Digests of the verification records this release was built from (sorted).
    pub inputs: Vec<Digest>,
    /// Sorted by indicator, unique.
    pub entries: Vec<ThreatEntry>,
    /// Sorted, unique.
    pub corrections: Vec<Correction>,
}

impl ThreatRelease {
    /// Looks up the entry matching `host` (exact or parent domain), most specific first.
    #[must_use]
    pub fn lookup(&self, host: &str) -> Option<&ThreatEntry> {
        let mut candidate = host;
        loop {
            if let Ok(i) = self
                .entries
                .binary_search_by(|e| e.indicator.as_str().cmp(candidate))
            {
                return self.entries.get(i);
            }
            match candidate.find('.') {
                Some(i) => candidate = &candidate[i + 1..],
                None => return None,
            }
        }
    }
}

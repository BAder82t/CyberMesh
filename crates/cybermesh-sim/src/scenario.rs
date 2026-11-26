use cybermesh_routing::Protection;
use serde::{Deserialize, Serialize};

/// Bytes a transport record adds to each share on every path (the MAC tag).
pub const RECORD_OVERHEAD: u64 = 16;

/// How wrong or altered shares are handled (mirrors `cybermesh_routing::Protection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionCfg {
    None,
    Authenticated,
    ReedSolomon,
}

impl From<ProtectionCfg> for Protection {
    fn from(p: ProtectionCfg) -> Self {
        match p {
            ProtectionCfg::None => Self::None,
            ProtectionCfg::Authenticated => Self::Authenticated,
            ProtectionCfg::ReedSolomon => Self::ReedSolomon,
        }
    }
}

/// What every session is planned to survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementCfg {
    /// Corrupt domains the plan assumes (`t`).
    pub corrupt_domains: usize,
    /// Extra path failures the plan absorbs (`f`).
    pub path_failures: usize,
    /// Whether corrupt domains alter shares (the simulator makes them do so) or only read them.
    pub tampering: bool,
    pub protection: ProtectionCfg,
}

/// The adversary's behaviour. The simulator **uses the true corrupt set** to judge outcomes; the
/// router learns of it only after `detect_ticks`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdversaryCfg {
    None,
    /// `corrupt_domains` domains, fixed for the whole run.
    Static {
        corrupt_domains: usize,
    },
    /// `corrupt_domains` domains at any moment; each tick, with probability `move_prob`, it moves
    /// to a fresh random set (a mobile adversary bounded by `corrupt_domains`).
    Mobile {
        corrupt_domains: usize,
        move_prob: f64,
    },
}

/// One reproducible experiment. The same scenario, including `seed`, gives the same report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Seed of the deterministic generator (`SimRng`, not production entropy).
    pub seed: u64,
    pub participants: usize,
    pub domains: usize,
    /// Cross-domain links added per participant (on top of a connecting ring and a ring inside
    /// every domain).
    pub extra_links_per_node: usize,
    pub latency_min_ms: u32,
    pub latency_max_ms: u32,
    /// Secret bytes in every link direction at the start.
    pub initial_secret: u64,
    /// Secret bytes added to every link direction each tick.
    pub replenish_per_tick: u64,
    pub sessions: usize,
    /// Payload bytes of each message (one message per session per tick).
    pub msg_bytes: u64,
    pub ticks: u32,
    pub requirement: RequirementCfg,
    pub adversary: AdversaryCfg,
    /// Probability per undirected link per tick that it fails.
    pub link_failure_prob: f64,
    pub link_repair_ticks: u32,
    /// Probability per domain per tick of an outage that takes down every link of its nodes.
    pub domain_outage_prob: f64,
    pub outage_ticks: u32,
    /// Ticks a domain must be corrupt before the router excludes it (`u32::MAX`: never).
    pub detect_ticks: u32,
    /// Weight of the secret-scarcity term in path cost.
    pub scarcity_weight: u64,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            seed: 1,
            participants: 300,
            domains: 30,
            extra_links_per_node: 3,
            latency_min_ms: 2,
            latency_max_ms: 40,
            initial_secret: 1 << 20,
            replenish_per_tick: 4096,
            sessions: 20,
            msg_bytes: 512,
            ticks: 60,
            requirement: RequirementCfg {
                corrupt_domains: 1,
                path_failures: 0,
                tampering: true,
                protection: ProtectionCfg::Authenticated,
            },
            adversary: AdversaryCfg::None,
            link_failure_prob: 0.0,
            link_repair_ticks: 3,
            domain_outage_prob: 0.0,
            outage_ticks: 4,
            detect_ticks: 3,
            scarcity_weight: 1,
        }
    }
}

/// Scenario and run failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SimError {
    #[error("invalid scenario: {0}")]
    Invalid(&'static str),
    #[error("scenario file: {0}")]
    Parse(String),
    #[error("routing: {0}")]
    Routing(String),
}

fn prob(p: f64) -> bool {
    (0.0..=1.0).contains(&p)
}

impl Scenario {
    /// # Errors
    /// [`SimError::Invalid`] naming what is wrong.
    pub fn validate(&self) -> Result<(), SimError> {
        if self.participants < 4 || self.participants > 20_000 {
            return Err(SimError::Invalid("participants must be 4..=20000"));
        }
        if self.domains < 3 || self.domains > self.participants {
            return Err(SimError::Invalid("domains must be 3..=participants"));
        }
        if self.latency_min_ms == 0 || self.latency_min_ms > self.latency_max_ms {
            return Err(SimError::Invalid(
                "latency range must satisfy 1 <= min <= max",
            ));
        }
        if self.sessions == 0 || self.ticks == 0 || self.msg_bytes == 0 {
            return Err(SimError::Invalid(
                "sessions, ticks and msg_bytes must be positive",
            ));
        }
        if ![self.link_failure_prob, self.domain_outage_prob]
            .iter()
            .all(|&p| prob(p))
        {
            return Err(SimError::Invalid("probabilities must be within 0..=1"));
        }
        match self.adversary {
            AdversaryCfg::None => {}
            AdversaryCfg::Static { corrupt_domains } => {
                if corrupt_domains > self.domains {
                    return Err(SimError::Invalid(
                        "adversary controls more domains than exist",
                    ));
                }
            }
            AdversaryCfg::Mobile {
                corrupt_domains,
                move_prob,
            } => {
                if corrupt_domains > self.domains || !prob(move_prob) {
                    return Err(SimError::Invalid(
                        "mobile adversary parameters out of range",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Parse a scenario file (TOML).
    ///
    /// # Errors
    /// [`SimError::Parse`] or [`SimError::Invalid`].
    pub fn from_toml(text: &str) -> Result<Self, SimError> {
        let s: Self = toml::from_str(text).map_err(|e| SimError::Parse(e.to_string()))?;
        s.validate()?;
        Ok(s)
    }

    /// The scenario as TOML, for the experiment record.
    ///
    /// # Errors
    /// [`SimError::Parse`] if serialisation fails.
    pub fn to_toml(&self) -> Result<String, SimError> {
        toml::to_string_pretty(self).map_err(|e| SimError::Parse(e.to_string()))
    }
}

use std::collections::{BTreeMap, BTreeSet};

/// An individual party (a node, an operator, a governance seat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId(pub u32);

/// An administrative domain: one organisation, one legal and operational boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub u32);

/// Registry failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("participant {0:?} is already registered")]
    AlreadyRegistered(ParticipantId),
    #[error("participant {0:?} is not registered")]
    UnknownParticipant(ParticipantId),
    #[error("participant {0:?} is already revoked")]
    AlreadyRevoked(ParticipantId),
    #[error("domain {0:?} has no participants")]
    UnknownDomain(DomainId),
    #[error("domain {0:?} is already marked compromised")]
    AlreadyCompromised(DomainId),
    #[error("domain {0:?} is not marked compromised")]
    NotCompromised(DomainId),
    #[error("invalid policy: {0}")]
    InvalidPolicy(&'static str),
    #[error("analysis refused: more than {0} domains")]
    TooManyDomains(usize),
}

/// Whether a participant may still act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Revoked,
}

/// A participant's current standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    pub domain: DomainId,
    pub status: Status,
    /// True when the participant's whole domain is marked compromised.
    pub domain_compromised: bool,
}

/// Participants, domains, revocations and compromises. `epoch` advances on every revocation,
/// compromise and readmission (not on registration), so approvals gathered before such a change
/// are stale.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    epoch: u64,
    entries: BTreeMap<ParticipantId, (DomainId, Status)>,
    compromised: BTreeSet<DomainId>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Add a participant to a domain. Does not change the epoch.
    ///
    /// # Errors
    /// [`PolicyError::AlreadyRegistered`].
    pub fn register(&mut self, p: ParticipantId, d: DomainId) -> Result<(), PolicyError> {
        if self.entries.contains_key(&p) {
            return Err(PolicyError::AlreadyRegistered(p));
        }
        self.entries.insert(p, (d, Status::Active));
        Ok(())
    }

    /// Revoke a participant for good (its id cannot be registered again). Advances the epoch.
    ///
    /// # Errors
    /// [`PolicyError::UnknownParticipant`], [`PolicyError::AlreadyRevoked`].
    pub fn revoke(&mut self, p: ParticipantId) -> Result<(), PolicyError> {
        let e = self
            .entries
            .get_mut(&p)
            .ok_or(PolicyError::UnknownParticipant(p))?;
        if e.1 == Status::Revoked {
            return Err(PolicyError::AlreadyRevoked(p));
        }
        e.1 = Status::Revoked;
        self.epoch += 1;
        Ok(())
    }

    /// Treat every participant of `d` as controlled by the adversary: none of them counts toward
    /// any authorisation, and the domain is excluded from eligibility. Advances the epoch.
    ///
    /// # Errors
    /// [`PolicyError::UnknownDomain`], [`PolicyError::AlreadyCompromised`].
    pub fn mark_domain_compromised(&mut self, d: DomainId) -> Result<(), PolicyError> {
        if !self.entries.values().any(|&(dom, _)| dom == d) {
            return Err(PolicyError::UnknownDomain(d));
        }
        if !self.compromised.insert(d) {
            return Err(PolicyError::AlreadyCompromised(d));
        }
        self.epoch += 1;
        Ok(())
    }

    /// Re-admit a domain after the operator has **re-provisioned its pairwise key material**
    /// (the registry cannot check that; old approval keys of a compromised domain are not safe).
    /// Advances the epoch.
    ///
    /// # Errors
    /// [`PolicyError::NotCompromised`].
    pub fn readmit_domain(&mut self, d: DomainId) -> Result<(), PolicyError> {
        if !self.compromised.remove(&d) {
            return Err(PolicyError::NotCompromised(d));
        }
        self.epoch += 1;
        Ok(())
    }

    /// Standing of a participant, if registered.
    #[must_use]
    pub fn standing(&self, p: ParticipantId) -> Option<Standing> {
        self.entries.get(&p).map(|&(domain, status)| Standing {
            domain,
            status,
            domain_compromised: self.compromised.contains(&domain),
        })
    }

    /// Every domain with at least one registered participant.
    #[must_use]
    pub fn domains(&self) -> BTreeSet<DomainId> {
        self.entries.values().map(|&(d, _)| d).collect()
    }

    /// Domains that could supply an approval: not compromised and with at least `min_per_domain`
    /// active participants.
    #[must_use]
    pub fn eligible_domains(&self, min_per_domain: usize) -> BTreeSet<DomainId> {
        self.domains()
            .into_iter()
            .filter(|d| !self.compromised.contains(d) && self.active_in(*d) >= min_per_domain)
            .collect()
    }

    /// Domains an adversary controlling them could approve with: at least `min_per_domain` active
    /// participants, compromised or not.
    pub(crate) fn capable_domains(&self, min_per_domain: usize) -> BTreeSet<DomainId> {
        self.domains()
            .into_iter()
            .filter(|d| self.active_in(*d) >= min_per_domain)
            .collect()
    }

    fn active_in(&self, d: DomainId) -> usize {
        self.entries
            .values()
            .filter(|&&(dom, st)| dom == d && st == Status::Active)
            .count()
    }
}

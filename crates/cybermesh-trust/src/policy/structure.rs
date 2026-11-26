use std::collections::{BTreeMap, BTreeSet};

use super::approvals::{Decision, Ignored};
use super::registry::{DomainId, ParticipantId, PolicyError, Registry, Status};

/// Largest number of domains the exhaustive analyses accept (they enumerate subsets).
pub const MAX_ANALYSIS_DOMAINS: usize = 20;

/// Which sets of domains are qualified to authorise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Structure {
    /// Any `min_domains` distinct domains.
    Threshold { min_domains: usize },
    /// Any set containing one of these minimal qualified sets.
    Minimal(Vec<BTreeSet<DomainId>>),
}

/// A structure plus how many active approvals one domain must supply for its vote to count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    structure: Structure,
    min_per_domain: usize,
}

impl Policy {
    /// # Errors
    /// [`PolicyError::InvalidPolicy`] for a zero threshold, zero `min_per_domain`, or an empty
    /// structure or empty qualified set (which would authorise with no approvals).
    pub fn new(structure: Structure, min_per_domain: usize) -> Result<Self, PolicyError> {
        if min_per_domain == 0 {
            return Err(PolicyError::InvalidPolicy(
                "min_per_domain must be at least 1",
            ));
        }
        match &structure {
            Structure::Threshold { min_domains: 0 } => {
                return Err(PolicyError::InvalidPolicy("threshold must be at least 1"));
            }
            Structure::Minimal(sets) if sets.is_empty() || sets.iter().any(BTreeSet::is_empty) => {
                return Err(PolicyError::InvalidPolicy(
                    "minimal sets must be non-empty and non-empty each",
                ));
            }
            _ => {}
        }
        Ok(Self {
            structure,
            min_per_domain,
        })
    }

    /// Approvals one domain must supply for its vote to count.
    #[must_use]
    pub fn min_per_domain(&self) -> usize {
        self.min_per_domain
    }

    /// Is this set of domains qualified?
    #[must_use]
    pub fn qualified(&self, domains: &BTreeSet<DomainId>) -> bool {
        match &self.structure {
            Structure::Threshold { min_domains } => domains.len() >= *min_domains,
            Structure::Minimal(sets) => sets.iter().any(|s| s.is_subset(domains)),
        }
    }

    /// Decide from approvals that are **already authenticated** (see [`super::Authoriser`] for
    /// the authenticated path). Counts domains, never participants.
    #[must_use]
    pub fn authorise(&self, registry: &Registry, approvals: &[ParticipantId]) -> Decision {
        let mut ignored = Vec::new();
        let mut seen = BTreeSet::new();
        let mut per_domain: BTreeMap<DomainId, usize> = BTreeMap::new();
        for &p in approvals {
            if !seen.insert(p) {
                ignored.push((p, Ignored::Duplicate));
                continue;
            }
            match registry.standing(p) {
                None => ignored.push((p, Ignored::Unknown)),
                Some(s) if s.status == Status::Revoked => ignored.push((p, Ignored::Revoked)),
                Some(s) if s.domain_compromised => {
                    ignored.push((p, Ignored::DomainCompromised));
                }
                Some(s) => *per_domain.entry(s.domain).or_default() += 1,
            }
        }
        let (counted, short): (BTreeSet<_>, BTreeSet<_>) = per_domain
            .iter()
            .map(|(&d, &n)| (d, n >= self.min_per_domain))
            .fold(
                (BTreeSet::new(), BTreeSet::new()),
                |(mut c, mut s), (d, ok)| {
                    if ok {
                        c.insert(d)
                    } else {
                        s.insert(d)
                    };
                    (c, s)
                },
            );
        Decision {
            authorised: self.qualified(&counted),
            counted_domains: counted,
            short_domains: short,
            ignored,
        }
    }
}

/// The domain sets that may be corrupt (or unavailable). Each listed set stands for itself and
/// every subset of it; list the maximal ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adversary(pub Vec<BTreeSet<DomainId>>);

impl Adversary {
    /// Every set of at most `t` of the given domains.
    ///
    /// # Errors
    /// [`PolicyError::TooManyDomains`] beyond [`MAX_ANALYSIS_DOMAINS`].
    pub fn any_up_to(domains: &BTreeSet<DomainId>, t: usize) -> Result<Self, PolicyError> {
        Ok(Self(subsets_of_size(domains, t)?))
    }
}

fn subsets_of_size(
    domains: &BTreeSet<DomainId>,
    size: usize,
) -> Result<Vec<BTreeSet<DomainId>>, PolicyError> {
    if domains.len() > MAX_ANALYSIS_DOMAINS {
        return Err(PolicyError::TooManyDomains(MAX_ANALYSIS_DOMAINS));
    }
    let v: Vec<DomainId> = domains.iter().copied().collect();
    let size = size.min(v.len());
    Ok((0u32..(1 << v.len()))
        .filter(|m| m.count_ones() as usize == size)
        .map(|m| {
            v.iter()
                .enumerate()
                .filter(|(i, _)| m >> i & 1 == 1)
                .map(|(_, &d)| d)
                .collect()
        })
        .collect())
}

/// Safety: can the adversary authorise on its own? An adversary controlling a set of domains can
/// approve for those that have enough registered active participants (compromise flags do not
/// help it). `Err` carries a corruptible set that is qualified.
///
/// # Errors
/// The counterexample set.
pub fn check_safety(
    policy: &Policy,
    registry: &Registry,
    adversary: &Adversary,
) -> Result<(), BTreeSet<DomainId>> {
    let capable = registry.capable_domains(policy.min_per_domain);
    for b in &adversary.0 {
        let usable: BTreeSet<_> = b.intersection(&capable).copied().collect();
        if policy.qualified(&usable) {
            return Err(b.clone());
        }
    }
    Ok(())
}

/// Liveness: if the given domain sets become unavailable, can the rest still authorise? Only
/// eligible domains (not compromised, enough active participants) count as available. `Err`
/// carries an unavailable set after which no qualified set remains.
///
/// # Errors
/// The counterexample set.
pub fn check_liveness(
    policy: &Policy,
    registry: &Registry,
    unavailable: &Adversary,
) -> Result<(), BTreeSet<DomainId>> {
    let eligible = registry.eligible_domains(policy.min_per_domain);
    for u in &unavailable.0 {
        let left: BTreeSet<_> = eligible.difference(u).copied().collect();
        if !policy.qualified(&left) {
            return Err(u.clone());
        }
    }
    Ok(())
}

/// Largest `m` such that **every** set of `m` domains is unable to authorise alone (the number of
/// simultaneously corrupt domains the policy tolerates), over the registry's capable domains.
/// `None` if even the empty set is qualified (never for a valid policy).
///
/// # Errors
/// [`PolicyError::TooManyDomains`].
pub fn max_safe_corruption(policy: &Policy, registry: &Registry) -> Result<usize, PolicyError> {
    let all = registry.domains();
    let mut best = 0;
    for m in 0..=all.len() {
        let adv = Adversary::any_up_to(&all, m)?;
        if check_safety(policy, registry, &adv).is_ok() {
            best = m;
        } else {
            break;
        }
    }
    Ok(best)
}

/// Largest `m` such that after **any** `m` eligible domains become unavailable, the rest can still
/// authorise.
///
/// # Errors
/// [`PolicyError::TooManyDomains`].
pub fn max_tolerable_loss(policy: &Policy, registry: &Registry) -> Result<usize, PolicyError> {
    let eligible = registry.eligible_domains(policy.min_per_domain);
    let mut best = 0;
    for m in 0..=eligible.len() {
        let adv = Adversary::any_up_to(&eligible, m)?;
        if check_liveness(policy, registry, &adv).is_ok() {
            best = m;
        } else {
            break;
        }
    }
    Ok(best)
}

/// The `Q^k` conditions on a general adversary structure: no `k` corruptible sets (repetition
/// allowed) cover all the domains. Hirt and Maurer's abstract states, in words, that the
/// no-two-sets-cover condition (`k = 2`) characterises **passive** adversaries and **active
/// adversaries with a broadcast channel**, and the no-three condition (`k = 3`) **active
/// adversaries without broadcast**; Cramer, Damgard and Maurer (Theorem 2) require `k = 2` for
/// passive security. See `docs/trust-fabric/literature-review.md` (`hirtmaurer1997`, `cdm2000`).
/// `Err` carries the covering sets.
///
/// # Errors
/// The `k` sets whose union is the whole domain set.
pub fn q_condition(
    adversary: &Adversary,
    all: &BTreeSet<DomainId>,
    k: usize,
) -> Result<(), Vec<BTreeSet<DomainId>>> {
    fn cover(
        sets: &[BTreeSet<DomainId>],
        all: &BTreeSet<DomainId>,
        left: usize,
        acc: &mut BTreeSet<DomainId>,
        pick: &mut Vec<BTreeSet<DomainId>>,
    ) -> bool {
        if left == 0 {
            return acc == all;
        }
        for s in sets {
            let saved = acc.clone();
            acc.extend(s.iter().copied());
            pick.push(s.clone());
            if cover(sets, all, left - 1, acc, pick) {
                return true;
            }
            pick.pop();
            *acc = saved;
        }
        false
    }
    let mut pick = Vec::new();
    if cover(&adversary.0, all, k, &mut BTreeSet::new(), &mut pick) {
        Err(pick)
    } else {
        Ok(())
    }
}

use std::collections::{BTreeMap, BTreeSet};

use cybermesh_entropy::Reservation;

use super::registry::{DomainId, ParticipantId, Registry, Status};
use super::structure::Policy;
use crate::block::Block;
use crate::mac::{MacError, TAG_LEN, Tag};

const DOMAIN: &[u8] = b"cybermesh-trust approval v1";

/// What a participant approves: one action in one session at one registry epoch. `seq` selects
/// the pad of the participant's block, so each approval a participant ever issues has its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval {
    pub participant: ParticipantId,
    /// Identifies the action being authorised (the caller defines the encoding).
    pub action: [u8; 16],
    /// The session this approval is for: an approval cannot be moved to another session.
    pub session: [u8; 16],
    /// Registry epoch at issue; approvals from before a revocation or compromise are stale.
    pub epoch: u64,
    pub seq: u32,
    /// Offset of the key block in the pairwise pool (public); ties the tag to one block.
    pub block_offset: u64,
}

impl Approval {
    fn message(&self, block: &Block) -> Vec<u8> {
        let mut m = DOMAIN.to_vec();
        m.extend_from_slice(&block.pool.0);
        m.extend_from_slice(&self.participant.0.to_be_bytes());
        m.extend_from_slice(&self.action);
        m.extend_from_slice(&self.session);
        m.extend_from_slice(&self.epoch.to_be_bytes());
        m.extend_from_slice(&self.seq.to_be_bytes());
        m.extend_from_slice(&self.block_offset.to_be_bytes());
        m
    }
}

/// An approval with its tag, as sent to the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaggedApproval {
    pub approval: Approval,
    tag: Tag,
}

impl TaggedApproval {
    /// For tests and wire decoding of the tag only; validity is decided by the verifier.
    #[must_use]
    pub fn with_tag(approval: Approval, tag: [u8; TAG_LEN]) -> Self {
        Self {
            approval,
            tag: Tag::from_bytes(tag),
        }
    }
    /// The raw tag bytes.
    #[must_use]
    pub fn tag_bytes(&self) -> [u8; TAG_LEN] {
        self.tag.to_bytes()
    }
}

/// Why an approval was not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("key block must be an Authentication reservation of 16 * (1 + n) bytes, 1 <= n <= 255")]
    BadMaterial,
    #[error("the participant has used all {0} approvals of its block")]
    Exhausted(u32),
    #[error("no key block is registered for this participant")]
    NoChannel,
    #[error("tag was made from a different key block")]
    WrongBlock,
    #[error("approval is for another action")]
    WrongAction,
    #[error("approval is for another session")]
    WrongSession,
    #[error("approval predates a revocation or compromise (epoch {got}, now {now})")]
    Stale { got: u64, now: u64 },
    #[error("sequence number beyond the key block")]
    BadSequence,
    #[error("this approval was already used for an authorisation")]
    Replay,
    #[error("tag does not verify")]
    BadTag,
    #[error("this participant's channel is retired after too many failures")]
    ChannelRetired,
    #[error("mac: {0}")]
    Mac(#[from] MacError),
}

/// The participant's side: issues approvals from its key block, one pad each, in order.
pub struct ApprovalIssuer {
    participant: ParticipantId,
    block: Block,
    next: u32,
}

impl core::fmt::Debug for ApprovalIssuer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApprovalIssuer")
            .field("participant", &self.participant)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl ApprovalIssuer {
    /// Take the participant's copy of its pairwise key block (consumed).
    ///
    /// # Errors
    /// [`ApprovalError::BadMaterial`].
    pub fn new(participant: ParticipantId, block: Reservation) -> Result<Self, ApprovalError> {
        Ok(Self {
            participant,
            block: Block::from_reservation(block).ok_or(ApprovalError::BadMaterial)?,
            next: 0,
        })
    }

    /// Approvals left in the block.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.block.slots().saturating_sub(self.next as usize)
    }

    /// Approve `action` in `session` at registry `epoch`, spending the next pad.
    ///
    /// # Errors
    /// [`ApprovalError::Exhausted`] when the block has no pads left.
    pub fn issue(
        &mut self,
        action: [u8; 16],
        session: [u8; 16],
        epoch: u64,
    ) -> Result<TaggedApproval, ApprovalError> {
        let pad = self
            .block
            .pad(self.next as usize)
            .ok_or(ApprovalError::Exhausted(self.next))?;
        let approval = Approval {
            participant: self.participant,
            action,
            session,
            epoch,
            seq: self.next,
            block_offset: self.block.offset,
        };
        let tag = self
            .block
            .key
            .tag_with_pad(&approval.message(&self.block), &pad)?;
        self.next += 1;
        Ok(TaggedApproval {
            approval,
            tag: Tag::from_bytes(tag),
        })
    }
}

/// Why an approval or participant was ignored in a [`Decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ignored {
    Unknown,
    Revoked,
    DomainCompromised,
    Duplicate,
    Rejected(ApprovalError),
    /// The action was already authorised once; it cannot be authorised again.
    AlreadyAuthorised,
}

/// Outcome of an authorisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub authorised: bool,
    /// Domains that cast a counting vote.
    pub counted_domains: BTreeSet<DomainId>,
    /// Domains that approved but supplied fewer than the policy's per-domain minimum.
    pub short_domains: BTreeSet<DomainId>,
    pub ignored: Vec<(ParticipantId, Ignored)>,
}

struct Channel {
    block: Block,
    used: BTreeSet<u32>,
    failures: u32,
}

/// The verifier's side: authenticates approvals under per-participant pairwise key blocks and
/// applies the policy. Private to this verifier (see the module docs).
pub struct Authoriser {
    policy: Policy,
    channels: BTreeMap<ParticipantId, Channel>,
    max_failures: u32,
    authorised: BTreeSet<[u8; 16]>,
}

impl core::fmt::Debug for Authoriser {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authoriser")
            .field("participants", &self.channels.len())
            .finish_non_exhaustive()
    }
}

impl Authoriser {
    /// `max_failures` bad tags retire a participant's channel.
    #[must_use]
    pub fn new(policy: Policy, max_failures: u32) -> Self {
        Self {
            policy,
            channels: BTreeMap::new(),
            max_failures,
            authorised: BTreeSet::new(),
        }
    }

    /// Take the verifier's copy of a participant's key block (consumed). Replaces any earlier one.
    ///
    /// # Errors
    /// [`ApprovalError::BadMaterial`].
    pub fn add_channel(
        &mut self,
        participant: ParticipantId,
        block: Reservation,
    ) -> Result<(), ApprovalError> {
        let block = Block::from_reservation(block).ok_or(ApprovalError::BadMaterial)?;
        self.channels.insert(
            participant,
            Channel {
                block,
                used: BTreeSet::new(),
                failures: 0,
            },
        );
        Ok(())
    }

    /// Failed tags counted against a participant's channel.
    #[must_use]
    pub fn failures(&self, participant: ParticipantId) -> u32 {
        self.channels.get(&participant).map_or(0, |c| c.failures)
    }

    fn check(
        &mut self,
        registry: &Registry,
        action: [u8; 16],
        session: [u8; 16],
        t: &TaggedApproval,
    ) -> Result<(), ApprovalError> {
        let a = &t.approval;
        let ch = self
            .channels
            .get_mut(&a.participant)
            .ok_or(ApprovalError::NoChannel)?;
        if ch.failures >= self.max_failures {
            return Err(ApprovalError::ChannelRetired);
        }
        if a.block_offset != ch.block.offset {
            return Err(ApprovalError::WrongBlock);
        }
        if a.action != action {
            return Err(ApprovalError::WrongAction);
        }
        if a.session != session {
            return Err(ApprovalError::WrongSession);
        }
        if a.epoch != registry.epoch() {
            return Err(ApprovalError::Stale {
                got: a.epoch,
                now: registry.epoch(),
            });
        }
        if ch.used.contains(&a.seq) {
            return Err(ApprovalError::Replay);
        }
        let pad = ch
            .block
            .pad(a.seq as usize)
            .ok_or(ApprovalError::BadSequence)?;
        let want = ch.block.key.tag_with_pad(&a.message(&ch.block), &pad)?;
        if Tag::from_bytes(want) == t.tag {
            Ok(())
        } else {
            ch.failures = ch.failures.saturating_add(1);
            Err(ApprovalError::BadTag)
        }
    }

    /// Authenticate the approvals for `action` in `session` against the registry's current
    /// epoch, then apply the policy to those that pass.
    ///
    /// Approvals that were used in an authorised decision are spent; ones that were not stay
    /// usable. An action that was authorised once is never authorised again.
    pub fn authorise(
        &mut self,
        registry: &Registry,
        action: [u8; 16],
        session: [u8; 16],
        approvals: &[TaggedApproval],
    ) -> Decision {
        if self.authorised.contains(&action) {
            return Decision {
                authorised: false,
                counted_domains: BTreeSet::new(),
                short_domains: BTreeSet::new(),
                ignored: approvals
                    .iter()
                    .map(|t| (t.approval.participant, Ignored::AlreadyAuthorised))
                    .collect(),
            };
        }
        let mut rejected = Vec::new();
        let mut good: Vec<&TaggedApproval> = Vec::new();
        for t in approvals {
            // A participant the registry no longer accepts is reported as such, not as a tag
            // failure, and costs no failure budget.
            match registry.standing(t.approval.participant) {
                None => rejected.push((t.approval.participant, Ignored::Unknown)),
                Some(s) if s.status == Status::Revoked => {
                    rejected.push((t.approval.participant, Ignored::Revoked));
                }
                Some(s) if s.domain_compromised => {
                    rejected.push((t.approval.participant, Ignored::DomainCompromised));
                }
                Some(_) => match self.check(registry, action, session, t) {
                    Ok(()) => good.push(t),
                    Err(e) => rejected.push((t.approval.participant, Ignored::Rejected(e))),
                },
            }
        }
        let ids: Vec<ParticipantId> = good.iter().map(|t| t.approval.participant).collect();
        let mut d = self.policy.authorise(registry, &ids);
        d.ignored.extend(rejected);
        if d.authorised {
            self.authorised.insert(action);
            for t in good {
                if let Some(ch) = self.channels.get_mut(&t.approval.participant) {
                    ch.used.insert(t.approval.seq);
                }
            }
        }
        d
    }
}

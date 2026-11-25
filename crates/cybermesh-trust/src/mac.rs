//! Wegman-Carter message authentication: polynomial hash over GF(2^128) plus a one-time pad.
//!
//! `tag = H_r(message) XOR pad`, where
//!
//! * `r` is a 128-bit hash key, uniform and secret, **reused** across messages;
//! * `pad` is 128 fresh uniform secret bits, **used for exactly one tag** (and, by the receiver,
//!   one verification);
//! * `H_r` evaluates the message, as blocks of 16 bytes (the last zero-padded) followed by a
//!   length block, as a polynomial in `r` by Horner's rule.
//!
//! # Security statement
//!
//! For two different messages of at most `n` blocks, the difference of their hashes is a
//! non-zero polynomial in `r` of degree at most `n + 1` (the coefficient of `r` is the message
//! length, so different lengths differ; equal-length messages differ in a block). It therefore
//! vanishes for at most `n + 1` of the `2^128` keys: `H` is `(n+1)/2^128`-almost-universal.
//! Because the pad is fresh and uniform for every tag, a tag reveals nothing about `r`, and an
//! adversary with **unbounded computation** that sees tags and makes `q` forgery attempts
//! succeeds with probability at most `q * (n + 1) / 2^128` ([`forgery_bound`]). This is the
//! standard Wegman-Carter argument; it is not re-proved here beyond the exhaustive check in the
//! tests of the polynomial claim over a small field.
//!
//! # What must hold
//!
//! * The hash key and every pad come from [`cybermesh_entropy`] pools of purpose
//!   `Authentication` and a shared-secret provenance. Pad reuse is prevented by construction (a
//!   [`Reservation`] is consumed by use), not by trust.
//! * Failed verifications are counted. [`Verifier`] refuses to verify once the budget is spent,
//!   so the bound above stays small; replace the key then.
//! * The two parties must use the same pad offset for the same message. Binding the session,
//!   direction and sequence number into the authenticated bytes (and therefore replay
//!   protection) is the transport's job; this module authenticates the bytes it is given.
//! * Comparison of tags is constant time; the field multiplication has no secret-dependent
//!   branches or table lookups. No timing review has been done.

use core::fmt;

use cybermesh_entropy::{Purpose, Reservation};
use zeroize::Zeroize;

/// Largest message accepted, bounding the degree of the hash polynomial.
pub const MAX_MESSAGE_LEN: usize = 16 << 20;
/// Tag, hash key and pad length in bytes.
pub const TAG_LEN: usize = 16;
/// Default budget of failed verifications per key.
pub const DEFAULT_MAX_FAILURES: u32 = 1 << 16;

/// Failures. None carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MacError {
    #[error(
        "key and pad material must be an Authentication reservation of exactly {TAG_LEN} bytes"
    )]
    BadMaterial,
    #[error("message longer than {MAX_MESSAGE_LEN} bytes")]
    MessageTooLong,
    #[error("authentication failed")]
    Invalid,
    #[error("too many failed verifications: this key is retired and must be replaced")]
    KeyRetired,
}

/// Multiplication in GF(2^128) with the polynomial `x^128 + x^7 + x^2 + x + 1`.
/// Branch-free: masks instead of conditionals, fixed 128 iterations.
fn gf_mul(a: u128, b: u128) -> u128 {
    let (mut a, mut acc) = (a, 0u128);
    for i in 0..128 {
        acc ^= a & 0u128.wrapping_sub((b >> i) & 1);
        a = (a << 1) ^ (0x87 & 0u128.wrapping_sub(a >> 127));
    }
    acc
}

/// Horner evaluation over blocks and a final length block, generic in the field so the
/// polynomial claim can be checked exhaustively over a small field.
fn hash_with<E: Copy>(
    blocks: impl IntoIterator<Item = E>,
    len: E,
    r: E,
    zero: E,
    add: impl Fn(E, E) -> E,
    mul: impl Fn(E, E) -> E,
) -> E {
    let acc = blocks.into_iter().fold(zero, |acc, b| mul(add(acc, b), r));
    mul(add(acc, len), r)
}

fn blocks(msg: &[u8]) -> impl Iterator<Item = u128> + '_ {
    msg.chunks(TAG_LEN).map(|c| {
        let mut b = [0u8; TAG_LEN];
        b[..c.len()].copy_from_slice(c);
        u128::from_be_bytes(b)
    })
}

fn poly_hash(r: u128, msg: &[u8]) -> u128 {
    hash_with(blocks(msg), msg.len() as u128, r, 0, |a, b| a ^ b, gf_mul)
}

/// A 16-byte authenticator.
#[derive(Clone, Copy)]
pub struct Tag([u8; TAG_LEN]);

impl Tag {
    /// The raw bytes, for the wire.
    #[must_use]
    pub fn to_bytes(self) -> [u8; TAG_LEN] {
        self.0
    }
    /// From the wire. Any 16 bytes decode; validity is decided by verification.
    #[must_use]
    pub fn from_bytes(b: [u8; TAG_LEN]) -> Self {
        Self(b)
    }
}

impl PartialEq for Tag {
    /// Constant time.
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(&other.0)
            .fold(0u8, |d, (a, b)| d | (a ^ b))
            == 0
    }
}
impl Eq for Tag {}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(..)")
    }
}

fn material(res: &Reservation) -> Result<[u8; TAG_LEN], MacError> {
    if res.purpose() != Purpose::Authentication || res.len() != TAG_LEN {
        return Err(MacError::BadMaterial);
    }
    let mut b = [0u8; TAG_LEN];
    b.copy_from_slice(res.as_bytes());
    Ok(b)
}

/// The reusable hash key. Zeroized on drop, redacted in `Debug`, not `Clone`.
pub struct MacKey {
    r: u128,
}

impl fmt::Debug for MacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacKey(..)")
    }
}

impl Drop for MacKey {
    fn drop(&mut self) {
        self.r.zeroize();
    }
}

impl MacKey {
    /// Build the key from a 16-byte `Authentication` reservation (consumed).
    ///
    /// # Errors
    /// [`MacError::BadMaterial`] for any other purpose or length.
    pub fn from_reservation(res: Reservation) -> Result<Self, MacError> {
        let mut b = material(&res)?;
        let r = u128::from_be_bytes(b);
        b.zeroize();
        Ok(Self { r })
    }

    fn raw_tag(&self, msg: &[u8], pad: &Reservation) -> Result<[u8; TAG_LEN], MacError> {
        let mut p = material(pad)?;
        let t = self.tag_with_pad(msg, &p);
        p.zeroize();
        t
    }

    /// Tag with pad bytes the caller already holds. The caller guarantees one tag per pad.
    pub(crate) fn tag_with_pad(
        &self,
        msg: &[u8],
        pad: &[u8; TAG_LEN],
    ) -> Result<[u8; TAG_LEN], MacError> {
        if msg.len() > MAX_MESSAGE_LEN {
            return Err(MacError::MessageTooLong);
        }
        Ok((poly_hash(self.r, msg) ^ u128::from_be_bytes(*pad)).to_be_bytes())
    }

    /// Key from raw bytes the caller took from an `Authentication` reservation.
    pub(crate) fn from_key_bytes(b: &[u8; TAG_LEN]) -> Self {
        Self {
            r: u128::from_be_bytes(*b),
        }
    }

    /// Tag `msg`, spending `pad` (a 16-byte `Authentication` reservation, consumed).
    ///
    /// # Errors
    /// [`MacError::BadMaterial`] or [`MacError::MessageTooLong`].
    pub fn tag(&self, msg: &[u8], pad: Reservation) -> Result<Tag, MacError> {
        self.raw_tag(msg, &pad).map(Tag)
    }
}

/// Verifies tags under one key and counts failures, retiring the key when the budget is spent.
#[derive(Debug)]
pub struct Verifier {
    key: MacKey,
    failures: u32,
    max_failures: u32,
}

impl Verifier {
    /// `max_failures` bounds how many forgery attempts the key will absorb.
    #[must_use]
    pub fn new(key: MacKey, max_failures: u32) -> Self {
        Self {
            key,
            failures: 0,
            max_failures,
        }
    }

    /// Failed verifications so far.
    #[must_use]
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Check `tag` on `msg`, spending `pad` (consumed even when the tag is wrong: it is spent).
    ///
    /// A bad `pad` reservation is not a forgery attempt and is not counted.
    ///
    /// # Errors
    /// [`MacError::Invalid`] on mismatch (counted), [`MacError::KeyRetired`] once
    /// `max_failures` mismatches have happened, [`MacError::BadMaterial`],
    /// [`MacError::MessageTooLong`].
    pub fn verify(&mut self, msg: &[u8], tag: &Tag, pad: Reservation) -> Result<(), MacError> {
        if self.failures >= self.max_failures {
            return Err(MacError::KeyRetired);
        }
        let want = Tag(self.key.raw_tag(msg, &pad)?);
        if want == *tag {
            Ok(())
        } else {
            self.failures = self.failures.saturating_add(1);
            Err(MacError::Invalid)
        }
    }
}

/// Upper bound on the probability that an unbounded adversary forges a tag, after `attempts`
/// failed verifications, for messages of at most `max_message_len` bytes:
/// `attempts * (blocks + 1) / 2^128`, with `blocks = ceil(len / 16)` plus the length block.
#[must_use]
pub fn forgery_bound(max_message_len: usize, attempts: u64) -> f64 {
    let degree = max_message_len.div_ceil(TAG_LEN) as f64 + 1.0;
    attempts as f64 * degree * 2f64.powi(-128)
}

#[cfg(test)]
mod tests;

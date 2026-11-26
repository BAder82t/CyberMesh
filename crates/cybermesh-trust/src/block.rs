//! A pairwise key block: one 16-byte hash key and `n` 16-byte pads from an `Authentication`
//! reservation. Shared by [`crate::shares`] (one pad per holder slot) and [`crate::policy`] (one
//! pad per approval sequence number). Zeroized on drop.

use cybermesh_entropy::{PoolId, Purpose, Reservation};
use zeroize::{Zeroize, Zeroizing};

use crate::mac::{MacKey, TAG_LEN};

pub(crate) struct Block {
    pub(crate) pool: PoolId,
    pub(crate) offset: u64,
    pub(crate) key: MacKey,
    pads: Zeroizing<Vec<u8>>,
}

impl Block {
    /// `None` unless `res` is an `Authentication` reservation of `16 * (1 + n)` bytes with
    /// `1 <= n <= 255`.
    pub(crate) fn from_reservation(res: Reservation) -> Option<Self> {
        let len = res.len();
        if res.purpose() != Purpose::Authentication
            || len < 2 * TAG_LEN
            || !len.is_multiple_of(TAG_LEN)
            || len / TAG_LEN - 1 > 255
        {
            return None;
        }
        let (pool, offset) = (res.pool(), res.offset());
        let secret = res.into_secret();
        let mut k = [0u8; TAG_LEN];
        k.copy_from_slice(&secret[..TAG_LEN]);
        let key = MacKey::from_key_bytes(&k);
        k.zeroize();
        Some(Self {
            pool,
            offset,
            key,
            pads: Zeroizing::new(secret[TAG_LEN..].to_vec()),
        })
    }

    /// Number of pad slots.
    pub(crate) fn slots(&self) -> usize {
        self.pads.len() / TAG_LEN
    }

    /// The pad of slot `slot` (0-based), if there is one.
    pub(crate) fn pad(&self, slot: usize) -> Option<[u8; TAG_LEN]> {
        let chunk = self.pads.chunks(TAG_LEN).nth(slot)?;
        let mut p = [0u8; TAG_LEN];
        p.copy_from_slice(chunk);
        Some(p)
    }
}

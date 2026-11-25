//! One-time secret-resource pools (EXPERIMENTAL, unaudited).
//!
//! Information-theoretic protocols consume secret material that two parties provisioned ahead
//! of time (one-time-pad bytes, authentication keys). Using any of it twice voids the guarantee.
//! This crate manages such material on disk so that **no byte is ever handed out twice, even
//! across crashes, restarts and concurrent processes**.
//!
//! # What kind of randomness is it?
//!
//! [`Provenance`] separates the kinds, and a pool refuses the ones that cannot support an
//! information-theoretic claim:
//!
//! | Provenance | Meaning | Accepted for |
//! |---|---|---|
//! | `ProvisionedShared` | secret bytes independently provisioned to both parties (courier, ceremony) | pads and authentication keys |
//! | `QuantumShared` | shared secret key from a QKD system | pads and authentication keys |
//! | `LocalSecret` | uniform secret bytes only this party has (OS randomness) | local secrets, never as a shared pad |
//! | `Pseudorandom` | deterministic expansion of a short seed | **never**: refused |
//! | `Public` | known to others | **never**: refused |
//!
//! The crate cannot verify provenance; it records what the operator declares and refuses the
//! declarations that are unsuitable. Local randomness does not become shared secret randomness
//! between remote parties by being stored here.
//!
//! # How a byte is spent
//!
//! 1. Under an exclusive file lock, the cursor is advanced past the requested region and
//!    **synced to disk first** (write-ahead).
//! 2. Only then are the bytes read and the region overwritten with zeros (best-effort erasure).
//! 3. The caller gets a [`Reservation`] that owns the bytes, zeroizes on drop and is not `Clone`.
//!
//! A crash at any point therefore *burns* material instead of re-issuing it. The cursor lives in
//! two checksummed slots written alternately, so a torn write leaves the previous slot intact.
//! If an old cursor is restored, the regions it points to were erased, so the pool fails closed
//! with [`EntropyError::Burned`] rather than issuing zeros or reused bytes.
//!
//! # Not covered
//!
//! * A restore of the *whole* pool directory from a backup resurrects erased material and cannot
//!   be detected locally. An external monotonic counter would be needed.
//! * Both parties must consume matching regions in the same order; this crate manages one
//!   party's copy and does not synchronise peers.
//! * Erasure is a file overwrite. Journaling file systems, snapshots and flash wear levelling can
//!   keep old copies.
//! * Reads of the pool are not constant time and the files are not encrypted.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"CMEPOOL1";
const HEADER_LEN: u64 = 8 + 1 + 1 + 16;
const SLOT_LEN: usize = 24;
/// Smallest reservation: erased regions are recognised by being all zero, which is only
/// meaningful (probability 2^-64 by chance) from 8 bytes.
pub const MIN_RESERVATION: usize = 8;
/// Largest single reservation (bounds memory use).
pub const MAX_RESERVATION: usize = 16 << 20;

/// Failures. None carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum EntropyError {
    #[error("provenance {0:?} cannot supply secret key material")]
    Unsuitable(Provenance),
    #[error("reservation must be {MIN_RESERVATION}..={MAX_RESERVATION} bytes")]
    InvalidLength,
    #[error("pool exhausted: {remaining} bytes remain, {requested} requested")]
    Exhausted { remaining: u64, requested: usize },
    #[error("the requested region was already consumed (erased): refusing to reuse it")]
    Burned,
    #[error("pool state is corrupt or does not belong to this pool: {0}")]
    Corrupt(&'static str),
    #[error("pool files are readable by other users")]
    Permissions,
    #[error("pool already exists")]
    Exists,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(test)]
    #[error("injected crash")]
    Injected,
}

/// Where the secret bytes came from. See the crate docs for what each may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Provenance {
    ProvisionedShared = 1,
    QuantumShared = 2,
    LocalSecret = 3,
    Pseudorandom = 4,
    Public = 5,
}

impl Provenance {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::ProvisionedShared,
            2 => Self::QuantumShared,
            3 => Self::LocalSecret,
            4 => Self::Pseudorandom,
            5 => Self::Public,
            _ => return None,
        })
    }
    /// Kinds a pool accepts.
    #[must_use]
    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Self::ProvisionedShared | Self::QuantumShared | Self::LocalSecret
        )
    }
    /// Kinds that are secret AND shared between the two parties (usable as a pad or MAC key
    /// between remote peers).
    #[must_use]
    pub fn is_shared_secret(self) -> bool {
        matches!(self, Self::ProvisionedShared | Self::QuantumShared)
    }
}

/// What the material of a pool may be spent on. Encryption and authentication material come from
/// separate pools: a reservation says which, so a MAC layer can refuse pad bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Encryption = 1,
    Authentication = 2,
    Local = 3,
}

impl Purpose {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Encryption,
            2 => Self::Authentication,
            3 => Self::Local,
            _ => return None,
        })
    }
}

/// 16-byte pool identifier, bound into every state file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolId(pub [u8; 16]);

/// Accounting for one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Bytes of material ever provisioned.
    pub capacity: u64,
    /// Bytes consumed or burned (the cursor).
    pub consumed: u64,
    /// Bytes still available.
    pub remaining: u64,
}

/// Bytes taken from a pool, exactly once. Zeroized on drop; not `Clone`; `Debug` is redacted.
pub struct Reservation {
    pool: PoolId,
    purpose: Purpose,
    offset: u64,
    bytes: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reservation")
            .field("offset", &self.offset)
            .field("len", &self.bytes.len())
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

impl Reservation {
    /// Pool this came from.
    #[must_use]
    pub fn pool(&self) -> PoolId {
        self.pool
    }
    /// What it may be spent on.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Position in the pool: two peers must use the same offsets for the same message.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Never true: reservations are at least [`MIN_RESERVATION`] bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// The secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Take the bytes out; the caller becomes responsible for them (still zeroized on drop).
    #[must_use]
    pub fn into_secret(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

struct Files {
    pool: File,
    cursor: File,
}

/// A pool of one-time secret material on disk.
pub struct Pool {
    id: PoolId,
    purpose: Purpose,
    provenance: Provenance,
    files: Mutex<Files>,
    #[cfg(test)]
    crash_after_cursor: std::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool")
            .field("id", &hex::encode(self.id.0))
            .field("purpose", &self.purpose)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

fn paths(dir: &Path, id: PoolId) -> (PathBuf, PathBuf) {
    let h = hex::encode(id.0);
    (
        dir.join(format!("{h}.pool")),
        dir.join(format!("{h}.cursor")),
    )
}

fn open_rw(path: &Path, create_new: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    if create_new {
        o.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn check_private(f: &File) -> Result<(), EntropyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(EntropyError::Permissions);
        }
    }
    let _ = f;
    Ok(())
}

fn slot_check(id: PoolId, seq: u64, cursor: u64) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"cybermesh-entropy cursor v1");
    h.update(id.0);
    h.update(seq.to_be_bytes());
    h.update(cursor.to_be_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

fn encode_slot(id: PoolId, seq: u64, cursor: u64) -> [u8; SLOT_LEN] {
    let mut s = [0u8; SLOT_LEN];
    s[..8].copy_from_slice(&seq.to_be_bytes());
    s[8..16].copy_from_slice(&cursor.to_be_bytes());
    s[16..].copy_from_slice(&slot_check(id, seq, cursor));
    s
}

fn decode_slot(id: PoolId, s: &[u8]) -> Option<(u64, u64)> {
    let seq = u64::from_be_bytes(s[..8].try_into().ok()?);
    let cursor = u64::from_be_bytes(s[8..16].try_into().ok()?);
    (s[16..SLOT_LEN] == slot_check(id, seq, cursor)).then_some((seq, cursor))
}

/// The valid slot with the highest sequence number: `(seq, cursor)`.
fn read_cursor(f: &mut File, id: PoolId) -> Result<(u64, u64), EntropyError> {
    let mut buf = [0u8; 2 * SLOT_LEN];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut buf)
        .map_err(|_| EntropyError::Corrupt("cursor file truncated"))?;
    [&buf[..SLOT_LEN], &buf[SLOT_LEN..]]
        .into_iter()
        .filter_map(|s| decode_slot(id, s))
        .max_by_key(|&(seq, _)| seq)
        .ok_or(EntropyError::Corrupt("no valid cursor slot"))
}

fn write_cursor(f: &mut File, id: PoolId, seq: u64, cursor: u64) -> Result<(), EntropyError> {
    // Alternate slots so a torn write damages only the slot that is not the current maximum.
    let at = (seq % 2) * SLOT_LEN as u64;
    f.seek(SeekFrom::Start(at))?;
    f.write_all(&encode_slot(id, seq, cursor))?;
    f.sync_data()?;
    Ok(())
}

fn capacity(pool: &File) -> Result<u64, EntropyError> {
    pool.metadata()?
        .len()
        .checked_sub(HEADER_LEN)
        .ok_or(EntropyError::Corrupt("pool file truncated"))
}

impl Pool {
    /// Provision a new pool from `material`. Refuses to overwrite and refuses provenances that
    /// cannot supply secret key material.
    ///
    /// # Errors
    /// [`EntropyError::Unsuitable`], [`EntropyError::Exists`], [`EntropyError::InvalidLength`]
    /// for empty material, or an I/O error.
    pub fn create(
        dir: &Path,
        id: PoolId,
        purpose: Purpose,
        provenance: Provenance,
        material: &[u8],
    ) -> Result<Self, EntropyError> {
        if !provenance.is_secret() {
            return Err(EntropyError::Unsuitable(provenance));
        }
        if material.is_empty() {
            return Err(EntropyError::InvalidLength);
        }
        let (pp, cp) = paths(dir, id);
        let mut pool = open_rw(&pp, true).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                EntropyError::Exists
            } else {
                e.into()
            }
        })?;
        let mut cursor = match open_rw(&cp, true) {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_file(&pp);
                return Err(if e.kind() == std::io::ErrorKind::AlreadyExists {
                    EntropyError::Exists
                } else {
                    e.into()
                });
            }
        };
        let mut head = Vec::with_capacity(HEADER_LEN as usize);
        head.extend_from_slice(MAGIC);
        head.push(provenance as u8);
        head.push(purpose as u8);
        head.extend_from_slice(&id.0);
        pool.write_all(&head)?;
        pool.write_all(material)?;
        pool.sync_all()?;
        // Slot 1 (seq 1) stays all-zero, which decodes as invalid; slot 0 holds seq 0.
        cursor.write_all(&encode_slot(id, 0, 0))?;
        cursor.write_all(&[0u8; SLOT_LEN])?;
        cursor.sync_all()?;
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(Self::from_parts(id, purpose, provenance, pool, cursor))
    }

    fn from_parts(
        id: PoolId,
        purpose: Purpose,
        provenance: Provenance,
        pool: File,
        cursor: File,
    ) -> Self {
        Self {
            id,
            purpose,
            provenance,
            files: Mutex::new(Files { pool, cursor }),
            #[cfg(test)]
            crash_after_cursor: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Open an existing pool, validating the header, the permissions and the cursor.
    ///
    /// # Errors
    /// [`EntropyError::Corrupt`] (fail closed) if the header or cursor state is damaged or
    /// belongs to another pool, [`EntropyError::Permissions`], or an I/O error.
    pub fn open(dir: &Path, id: PoolId) -> Result<Self, EntropyError> {
        let (pp, cp) = paths(dir, id);
        let mut pool = open_rw(&pp, false)?;
        let mut cursor = open_rw(&cp, false)?;
        check_private(&pool)?;
        check_private(&cursor)?;
        let mut head = [0u8; HEADER_LEN as usize];
        pool.read_exact(&mut head)
            .map_err(|_| EntropyError::Corrupt("pool header truncated"))?;
        if &head[..8] != MAGIC || head[10..26] != id.0 {
            return Err(EntropyError::Corrupt("bad magic or pool id"));
        }
        let provenance = Provenance::from_u8(head[8])
            .filter(|p| p.is_secret())
            .ok_or(EntropyError::Corrupt("bad provenance"))?;
        let purpose = Purpose::from_u8(head[9]).ok_or(EntropyError::Corrupt("bad purpose"))?;
        let (_, cur) = read_cursor(&mut cursor, id)?;
        if cur > capacity(&pool)? {
            return Err(EntropyError::Corrupt("cursor beyond pool"));
        }
        Ok(Self::from_parts(id, purpose, provenance, pool, cursor))
    }

    /// Pool id.
    #[must_use]
    pub fn id(&self) -> PoolId {
        self.id
    }
    /// What the material may be spent on.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Declared provenance.
    #[must_use]
    pub fn provenance(&self) -> Provenance {
        self.provenance
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Files>, EntropyError> {
        let g = self
            .files
            .lock()
            .map_err(|_| EntropyError::Corrupt("pool poisoned by a panic"))?;
        // Cross-process exclusion; the mutex covers threads sharing this handle.
        g.cursor.lock()?;
        Ok(g)
    }

    /// Current accounting.
    ///
    /// # Errors
    /// Corrupt state or an I/O error.
    pub fn stats(&self) -> Result<Stats, EntropyError> {
        let mut g = self.lock()?;
        let r = (|| {
            let (_, consumed) = read_cursor(&mut g.cursor, self.id)?;
            let capacity = capacity(&g.pool)?;
            Ok(Stats {
                capacity,
                consumed,
                remaining: capacity.saturating_sub(consumed),
            })
        })();
        let _ = g.cursor.unlock();
        r
    }

    /// True when fewer than `low_water` bytes remain: time to replenish.
    ///
    /// # Errors
    /// As [`Pool::stats`].
    pub fn needs_replenishment(&self, low_water: u64) -> Result<bool, EntropyError> {
        Ok(self.stats()?.remaining < low_water)
    }

    /// Take `len` unused bytes, exactly once.
    ///
    /// The cursor is advanced and synced before the bytes are read. If the requested region is
    /// already erased (an old cursor was restored), fails with [`EntropyError::Burned`]; the
    /// cursor stays advanced, so the region is never offered again.
    ///
    /// # Errors
    /// [`EntropyError::InvalidLength`], [`EntropyError::Exhausted`] (cursor unchanged),
    /// [`EntropyError::Burned`], corrupt state or an I/O error.
    pub fn reserve(&self, len: usize) -> Result<Reservation, EntropyError> {
        if !(MIN_RESERVATION..=MAX_RESERVATION).contains(&len) {
            return Err(EntropyError::InvalidLength);
        }
        let mut g = self.lock()?;
        let r = self.reserve_locked(&mut g, len);
        let _ = g.cursor.unlock();
        r
    }

    fn reserve_locked(&self, g: &mut Files, len: usize) -> Result<Reservation, EntropyError> {
        let (seq, cur) = read_cursor(&mut g.cursor, self.id)?;
        let cap = capacity(&g.pool)?;
        let end =
            cur.checked_add(len as u64)
                .filter(|&e| e <= cap)
                .ok_or(EntropyError::Exhausted {
                    remaining: cap.saturating_sub(cur),
                    requested: len,
                })?;
        // 1. Write-ahead: the region is spent from here on, whatever happens next.
        write_cursor(&mut g.cursor, self.id, seq + 1, end)?;
        #[cfg(test)]
        if self
            .crash_after_cursor
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(EntropyError::Injected);
        }
        // 2. Read, then erase.
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        g.pool.seek(SeekFrom::Start(HEADER_LEN + cur))?;
        g.pool.read_exact(&mut bytes)?;
        if bytes.iter().all(|&b| b == 0) {
            return Err(EntropyError::Burned);
        }
        g.pool.seek(SeekFrom::Start(HEADER_LEN + cur))?;
        g.pool.write_all(&vec![0u8; len])?;
        g.pool.sync_data()?;
        Ok(Reservation {
            pool: self.id,
            purpose: self.purpose,
            offset: cur,
            bytes,
        })
    }

    /// Append freshly provisioned material. Both peers must append identical bytes in the same
    /// order; this crate does not check that.
    ///
    /// # Errors
    /// [`EntropyError::InvalidLength`] for empty material, or an I/O error.
    pub fn replenish(&self, material: &[u8]) -> Result<(), EntropyError> {
        if material.is_empty() {
            return Err(EntropyError::InvalidLength);
        }
        let mut g = self.lock()?;
        let r = (|| {
            g.pool.seek(SeekFrom::End(0))?;
            g.pool.write_all(material)?;
            g.pool.sync_all()?;
            Ok(())
        })();
        let _ = g.cursor.unlock();
        r
    }
}

#[cfg(test)]
mod tests;

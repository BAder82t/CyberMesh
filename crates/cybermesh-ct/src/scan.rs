//! Deterministic brand-lookalike scanning of data tiles.

use cybermesh_analysis::{Engine, normalize_domain};
use cybermesh_crypto::Digest;
use cybermesh_protocol::FindingCode;
use cybermesh_protocol::ct::{
    CtMatch, MAX_MATCHES_PER_ENTRY, MAX_MATCHES_PER_TILE, MAX_NAMES_PER_TILE, TileScanResult,
};
use sha2::{Digest as _, Sha256};

use crate::names::certificate_names;
use crate::tile::{Entry, parse_data_tile, tile_root};
use crate::{CtError, TileSource};

/// Domain separation for [`TileScanResult::names_digest`].
const NAMES_DIGEST_TAG: &[u8] = b"cybermesh/ct-names/v1";

/// Findings that indicate impersonation of a protected brand.
#[must_use]
pub fn is_brand_signal(code: FindingCode) -> bool {
    matches!(
        code,
        FindingCode::BrandImpersonation | FindingCode::BrandLookalike | FindingCode::IdnHomograph
    )
}

/// Priority order for keeping matches when a cap applies: highest risk first, then entry
/// index, then name. Total and deterministic.
fn priority(a: &CtMatch, b: &CtMatch) -> std::cmp::Ordering {
    b.risk_score_bp
        .cmp(&a.risk_score_bp)
        .then(a.index.cmp(&b.index))
        .then_with(|| a.name.cmp(&b.name))
}

/// Scans one full data tile. Output depends only on the tile bytes, the tile index and the
/// engine (version + evidence), so independent workers produce identical results.
///
/// - Every extracted name is committed in `names_digest` (entry index, name), up to
///   [`MAX_NAMES_PER_TILE`] names per tile.
/// - At most [`MAX_MATCHES_PER_ENTRY`] matches are kept per certificate and at most
///   [`MAX_MATCHES_PER_TILE`] per tile, by priority (highest risk first), so a certificate
///   with many decoy names cannot push a high-risk name out of the result.
/// - `truncated` is set when any cap applied.
pub fn scan_tile(
    bytes: &[u8],
    tile_index: u64,
    engine: &Engine,
) -> Result<TileScanResult, CtError> {
    scan_entries(&parse_data_tile(bytes, tile_index)?, tile_index, engine)
}

/// Scans the 256 entries of tile `tile_index`, as [`scan_tile`] does for a data tile.
pub fn scan_entries(
    entries: &[Entry],
    tile_index: u64,
    engine: &Engine,
) -> Result<TileScanResult, CtError> {
    let root = Digest(tile_root(entries));
    let mut unparsed: u16 = 0;
    let mut names: u32 = 0;
    let mut truncated = false;
    let mut digest = Sha256::new();
    digest.update(NAMES_DIGEST_TAG);
    digest.update([0u8]);
    let mut matches = Vec::new();
    for e in entries {
        let Ok(raw) = certificate_names(e) else {
            unparsed += 1;
            continue;
        };
        let mut normalized: Vec<String> = raw
            .iter()
            .filter_map(|r| normalize_domain(r).ok())
            .collect();
        normalized.sort();
        normalized.dedup();
        let mut entry_matches = Vec::new();
        for domain in normalized {
            if names >= MAX_NAMES_PER_TILE {
                truncated = true;
                break;
            }
            names += 1;
            digest.update(e.index.to_be_bytes());
            digest.update((domain.len() as u64).to_be_bytes());
            digest.update(domain.as_bytes());
            let a = engine
                .assess(&domain)
                .map_err(|err| CtError::Analysis(err.to_string()))?;
            if a.findings.iter().any(|f| is_brand_signal(f.code)) {
                let mut codes: Vec<FindingCode> = a.findings.iter().map(|f| f.code).collect();
                codes.sort();
                codes.dedup();
                entry_matches.push(CtMatch {
                    index: e.index,
                    name: domain,
                    risk_score_bp: a.risk_score_bp,
                    verdict: a.verdict,
                    codes,
                });
            }
        }
        if entry_matches.len() > MAX_MATCHES_PER_ENTRY {
            entry_matches.sort_by(priority);
            entry_matches.truncate(MAX_MATCHES_PER_ENTRY);
            truncated = true;
        }
        matches.append(&mut entry_matches);
    }
    if matches.len() > MAX_MATCHES_PER_TILE {
        matches.sort_by(priority);
        matches.truncate(MAX_MATCHES_PER_TILE);
        truncated = true;
    }
    matches.sort_by(|a, b| (a.index, &a.name).cmp(&(b.index, &b.name)));
    Ok(TileScanResult {
        tile_index,
        leaf_count: 256,
        root,
        unparsed,
        names,
        names_digest: Digest(digest.finalize().into()),
        matches,
        truncated,
    })
}

/// Fetches and scans consecutive full tiles. Returns the results and the bytes downloaded.
pub fn scan_tiles(
    source: &dyn TileSource,
    first_tile: u64,
    tile_count: u32,
    engine: &Engine,
) -> Result<(Vec<TileScanResult>, u64), CtError> {
    let mut out = Vec::with_capacity(tile_count as usize);
    let mut bytes = 0u64;
    for i in 0..u64::from(tile_count) {
        let n = first_tile
            .checked_add(i)
            .ok_or_else(|| CtError::Malformed("tile range overflow".into()))?;
        let (entries, size) = source.entries(n)?;
        bytes += size as u64;
        out.push(scan_entries(&entries, n, engine)?);
    }
    Ok((out, bytes))
}

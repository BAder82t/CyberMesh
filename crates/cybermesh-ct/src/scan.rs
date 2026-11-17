//! Deterministic brand-lookalike scanning of data tiles.

use cybermesh_analysis::{Engine, normalize_domain};
use cybermesh_crypto::Digest;
use cybermesh_protocol::FindingCode;
use cybermesh_protocol::ct::{CtMatch, MAX_MATCHES_PER_TILE, TileScanResult};

use crate::names::certificate_names;
use crate::tile::{parse_data_tile, tile_root};
use crate::{CtError, TileSource};

/// Findings that indicate impersonation of a protected brand.
#[must_use]
pub fn is_brand_signal(code: FindingCode) -> bool {
    matches!(
        code,
        FindingCode::BrandImpersonation | FindingCode::BrandLookalike | FindingCode::IdnHomograph
    )
}

/// Scans one full data tile. Output depends only on the tile bytes, the tile index and the
/// engine (version + evidence), so independent workers produce identical results.
pub fn scan_tile(
    bytes: &[u8],
    tile_index: u64,
    engine: &Engine,
) -> Result<TileScanResult, CtError> {
    let entries = parse_data_tile(bytes, tile_index)?;
    let root = Digest(tile_root(&entries));
    let mut unparsed: u16 = 0;
    let mut matches = Vec::new();
    for e in &entries {
        let Ok(names) = certificate_names(e) else {
            unparsed += 1;
            continue;
        };
        for raw in names {
            let Ok(domain) = normalize_domain(&raw) else {
                continue;
            };
            let a = engine
                .assess(&domain)
                .map_err(|err| CtError::Analysis(err.to_string()))?;
            if a.findings.iter().any(|f| is_brand_signal(f.code)) {
                let mut codes: Vec<FindingCode> = a.findings.iter().map(|f| f.code).collect();
                codes.sort();
                codes.dedup();
                matches.push(CtMatch {
                    index: e.index,
                    name: domain,
                    risk_score_bp: a.risk_score_bp,
                    verdict: a.verdict,
                    codes,
                });
            }
        }
    }
    matches.sort_by(|a, b| (a.index, &a.name).cmp(&(b.index, &b.name)));
    matches.dedup_by(|a, b| a.index == b.index && a.name == b.name);
    let truncated = matches.len() > MAX_MATCHES_PER_TILE;
    matches.truncate(MAX_MATCHES_PER_TILE);
    Ok(TileScanResult {
        tile_index,
        leaf_count: 256,
        root,
        unparsed,
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
        let data = source.data_tile(n)?;
        bytes += data.len() as u64;
        out.push(scan_tile(&data, n, engine)?);
    }
    Ok((out, bytes))
}

//! HTTPS access to a static CT monitoring prefix.
//!
//! The base URL comes only from pinned `ct-logs` evidence (validated: HTTPS, or HTTP to a
//! loopback host). Requests never follow redirects, have timeouts, and responses are capped
//! at [`MAX_TILE_BYTES`](crate::MAX_TILE_BYTES). Only fixed tile and checkpoint paths
//! derived from integers are requested.

use std::io::Read as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use cybermesh_analysis::CtLogInfo;

use crate::tile::{data_tile_path, hash_tile_path};
use crate::{CtError, MAX_TILE_BYTES, TileSource};

static BYTES: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Bytes received (after decompression) and requests made by every [`HttpTileSource`] in
/// this process, for resource reports. Requests that fail are counted too. Several nodes in
/// one process (as in tests) share these totals.
#[must_use]
pub fn transfer_totals() -> (u64, u64) {
    (
        BYTES.load(Ordering::Relaxed),
        REQUESTS.load(Ordering::Relaxed),
    )
}

/// Static CT client for one log.
#[derive(Debug, Clone)]
pub struct HttpTileSource {
    base: String,
    agent: ureq::Agent,
}

impl HttpTileSource {
    /// Creates a client for a validated, pinned log.
    pub fn new(log: &CtLogInfo, timeout: Duration) -> Result<Self, CtError> {
        log.validate().map_err(CtError::Http)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(0)
            .user_agent("cybermesh-ct-monitor (+https://github.com/BAder82t/CyberMesh)")
            .build();
        Ok(Self {
            base: log.monitoring_url.clone(),
            agent,
        })
    }

    fn get(&self, path: &str, max: usize) -> Result<Vec<u8>, CtError> {
        let url = format!("{}{path}", self.base);
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let resp = match self.agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => return Err(CtError::NotFound(path.to_owned())),
            Err(e) => return Err(CtError::Http(e.to_string())),
        };
        // Redirects are disabled, so a 3xx arrives here: only 200 carries a tile.
        if resp.status() != 200 {
            return Err(CtError::Http(format!(
                "unexpected status {}",
                resp.status()
            )));
        }
        let mut body = Vec::new();
        resp.into_reader()
            .take(max as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| CtError::Http(e.to_string()))?;
        BYTES.fetch_add(body.len() as u64, Ordering::Relaxed);
        if body.len() > max {
            return Err(CtError::TooLarge);
        }
        Ok(body)
    }
}

/// Classic RFC 6962 client for one log: only the four read calls, on the pinned base URL.
/// Requests never follow redirects, have timeouts, and responses are capped at
/// [`MAX_RESPONSE_BYTES`](crate::rfc6962::MAX_RESPONSE_BYTES). Paths and queries are built
/// only from integers and base64 of hashes.
#[derive(Debug, Clone)]
pub struct HttpLogApi {
    inner: HttpTileSource,
}

impl HttpLogApi {
    /// Creates a client for a validated, pinned log whose `monitoring_url` is the log's API
    /// prefix (the part before `ct/v1/`).
    pub fn new(log: &CtLogInfo, timeout: Duration) -> Result<Self, CtError> {
        Ok(Self {
            inner: HttpTileSource::new(log, timeout)?,
        })
    }

    fn get(&self, path_and_query: &str) -> Result<Vec<u8>, CtError> {
        self.inner
            .get(path_and_query, crate::rfc6962::MAX_RESPONSE_BYTES)
    }
}

impl crate::rfc6962::LogApi for HttpLogApi {
    fn get_sth(&self) -> Result<crate::rfc6962::Sth, CtError> {
        crate::rfc6962::parse_sth(&self.get("ct/v1/get-sth")?)
    }

    fn get_entries(&self, start: u64, end: u64) -> Result<Vec<Vec<u8>>, CtError> {
        crate::rfc6962::parse_entries(
            &self.get(&format!("ct/v1/get-entries?start={start}&end={end}"))?,
        )
    }

    fn get_proof_by_hash(
        &self,
        leaf_hash: &[u8; 32],
        tree_size: u64,
    ) -> Result<(u64, Vec<[u8; 32]>), CtError> {
        use base64::Engine as _;
        // The standard alphabet contains `+`, `/` and `=`, which a query must escape.
        let h = base64::engine::general_purpose::STANDARD
            .encode(leaf_hash)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        crate::rfc6962::parse_proof(&self.get(&format!(
            "ct/v1/get-proof-by-hash?hash={h}&tree_size={tree_size}"
        ))?)
    }

    fn get_sth_consistency(&self, first: u64, second: u64) -> Result<Vec<[u8; 32]>, CtError> {
        crate::rfc6962::parse_consistency(&self.get(&format!(
            "ct/v1/get-sth-consistency?first={first}&second={second}"
        ))?)
    }
}

impl TileSource for HttpTileSource {
    fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError> {
        self.get(&data_tile_path(n), MAX_TILE_BYTES)
    }

    fn hash_tile(&self, level: u8, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
        self.get(&hash_tile_path(level, n, width), 8192)
    }

    fn checkpoint(&self) -> Result<String, CtError> {
        let b = self.get("checkpoint", 64 * 1024)?;
        String::from_utf8(b).map_err(|_| CtError::Malformed("checkpoint is not UTF-8".into()))
    }
}

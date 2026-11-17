//! HTTPS access to a static CT monitoring prefix.
//!
//! The base URL comes only from pinned `ct-logs` evidence (validated: HTTPS, or HTTP to a
//! loopback host). Requests never follow redirects, have timeouts, and responses are capped
//! at [`MAX_TILE_BYTES`](crate::MAX_TILE_BYTES). Only fixed tile and checkpoint paths
//! derived from integers are requested.

use std::io::Read as _;
use std::time::Duration;

use cybermesh_analysis::CtLogInfo;

use crate::tile::{data_tile_path, hash_tile_path};
use crate::{CtError, MAX_TILE_BYTES, TileSource};

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
        if body.len() > max {
            return Err(CtError::TooLarge);
        }
        Ok(body)
    }
}

impl TileSource for HttpTileSource {
    fn data_tile(&self, n: u64) -> Result<Vec<u8>, CtError> {
        self.get(&data_tile_path(n), MAX_TILE_BYTES)
    }

    fn level1_tile(&self, n: u64, width: Option<u8>) -> Result<Vec<u8>, CtError> {
        self.get(&hash_tile_path(1, n, width), 8192)
    }

    fn checkpoint(&self) -> Result<String, CtError> {
        let b = self.get("checkpoint", 64 * 1024)?;
        String::from_utf8(b).map_err(|_| CtError::Malformed("checkpoint is not UTF-8".into()))
    }
}

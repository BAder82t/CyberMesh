//! Minimal static server for the local demonstration.
//!
//! * Requests whose Host ends in `.phish.localhost` receive a built-in, clearly labelled
//!   phishing *test* page for a fictional bank. Its form cannot submit anywhere.
//! * Other requests serve files from `--dir` (no directory listing, no path traversal).
//!
//! Binds to loopback by default. Intended for demonstrations only.

use std::path::{Component, Path, PathBuf};

use anyhow::{Result, anyhow};

const TEST_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ExampleBank - Sign in (CyberMesh TEST PAGE)</title>
<style>
body{font-family:system-ui,sans-serif;background:#f4f6f8;margin:0}
.banner{background:#b00020;color:#fff;padding:12px 16px;font-weight:600}
.card{max-width:360px;margin:48px auto;background:#fff;border-radius:8px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,.15)}
input{display:block;width:100%;box-sizing:border-box;margin:8px 0 16px;padding:8px}
button{padding:10px 16px}
</style></head>
<body>
<div class="banner">CyberMesh demonstration: this is a locally served, simulated phishing page for a fictional brand. It collects nothing.</div>
<div class="card">
<h1>ExampleBank</h1>
<p>Please verify your account to continue.</p>
<form onsubmit="return false" autocomplete="off">
<label>Username<input name="u" disabled></label>
<label>Password<input name="p" type="password" disabled></label>
<button type="button" disabled>Sign in</button>
</form>
</div>
</body></html>
"#;

fn content_type(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()) {
        Some("json") => "application/json",
        Some("html") => "text/html; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Extensions that may be served. Key files (`*.key.json`) are always refused.
const SERVABLE: &[&str] = &["json", "txt", "html"];

/// Resolves a URL path inside `root` (which must be canonical), refusing traversal, hidden
/// files, key files, non-allowlisted extensions and symlinks that escape `root`.
fn resolve(root: &Path, url: &str) -> Option<PathBuf> {
    let path = url.split(['?', '#']).next().unwrap_or("/");
    let rel = Path::new(path.trim_start_matches('/'));
    let mut out = root.to_path_buf();
    for c in rel.components() {
        match c {
            Component::Normal(s) if !s.to_string_lossy().starts_with('.') => out.push(s),
            _ => return None,
        }
    }
    let name = out.file_name()?.to_string_lossy().to_ascii_lowercase();
    let ext_ok = out
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SERVABLE.contains(&e.to_ascii_lowercase().as_str()));
    if !ext_ok || name.ends_with(".key.json") || name.contains("secret") {
        return None;
    }
    let real = out.canonicalize().ok()?;
    (real.starts_with(root) && real.is_file()).then_some(real)
}

pub fn serve(dir: &Path, addr: &str, allow_non_loopback: bool) -> Result<()> {
    let sock: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow!("bad address {addr}: {e}"))?;
    if !sock.ip().is_loopback() && !allow_non_loopback {
        return Err(anyhow!(
            "refusing to bind {addr}: not a loopback address (pass --public to serve on the network)"
        ));
    }
    let server = tiny_http::Server::http(addr).map_err(|e| anyhow!("bind {addr}: {e}"))?;
    eprintln!(
        "serving {} on http://{addr} (phishing test page on *.phish.localhost)",
        dir.display()
    );
    let root = dir.canonicalize()?;
    let header = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).ok();
    for req in server.incoming_requests() {
        let host = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let hostname = host.split(':').next().unwrap_or("");
        let resp = if hostname.ends_with(".phish.localhost") {
            let mut r = tiny_http::Response::from_string(TEST_PAGE);
            if let Some(h) = header("Content-Type", "text/html; charset=utf-8") {
                r.add_header(h);
            }
            r
        } else if let Some(p) = resolve(&root, req.url()) {
            match std::fs::read(&p) {
                Ok(b) => {
                    let mut r = tiny_http::Response::from_data(b);
                    if let Some(h) = header("Content-Type", content_type(&p)) {
                        r.add_header(h);
                    }
                    r
                }
                Err(_) => tiny_http::Response::from_string("error").with_status_code(500),
            }
        } else {
            tiny_http::Response::from_string("not found").with_status_code(404)
        };
        let mut resp = resp;
        if let Some(h) = header("Cache-Control", "no-store") {
            resp.add_header(h);
        }
        if let Some(h) = header("X-Content-Type-Options", "nosniff") {
            resp.add_header(h);
        }
        let _ = req.respond(resp);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_traversal_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("release.json"), b"{}").unwrap();
        std::fs::write(dir.path().join(".secret"), b"x").unwrap();
        let root = dir.path().canonicalize().unwrap();
        assert!(resolve(&root, "/release.json").is_some());
        assert!(resolve(&root, "/release.json?x=1").is_some());
        assert!(resolve(&root, "/../etc/passwd").is_none());
        assert!(resolve(&root, "/.secret").is_none());
        assert!(resolve(&root, "/").is_none());
        assert!(resolve(&root, "//etc/passwd").is_none());
    }

    #[test]
    fn key_files_symlink_escapes_and_unknown_types_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("keys")).unwrap();
        std::fs::write(dir.path().join("keys/gov-1.key.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("binary.bin"), b"x").unwrap();
        std::fs::write(outside.path().join("leak.json"), b"{}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            outside.path().join("leak.json"),
            dir.path().join("link.json"),
        )
        .unwrap();
        let root = dir.path().canonicalize().unwrap();
        assert!(resolve(&root, "/keys/gov-1.key.json").is_none());
        assert!(resolve(&root, "/KEYS/GOV-1.KEY.JSON").is_none());
        assert!(resolve(&root, "/binary.bin").is_none());
        #[cfg(unix)]
        assert!(
            resolve(&root, "/link.json").is_none(),
            "symlink escaping the root"
        );
    }
}

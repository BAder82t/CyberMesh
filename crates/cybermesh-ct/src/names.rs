//! DNS names from logged certificates.

use x509_parser::prelude::*;

use crate::CtError;
use crate::tile::{Entry, EntryKind};

/// Upper bound on names taken from one certificate (bounds work on hostile certificates).
pub const MAX_NAMES_PER_CERT: usize = 1000;

/// Subject common names and SAN `dNSName`s, lowercased, wildcard prefix and trailing dot
/// removed, sorted and de-duplicated. Names are *not* validated here.
pub fn certificate_names(entry: &Entry) -> Result<Vec<String>, CtError> {
    let tbs = match entry.kind {
        EntryKind::X509 => {
            let (_, cert) = X509Certificate::from_der(&entry.der)
                .map_err(|e| CtError::Malformed(format!("certificate: {e}")))?;
            cert.tbs_certificate
        }
        EntryKind::Precert => {
            let (_, tbs) = TbsCertificate::from_der(&entry.der)
                .map_err(|e| CtError::Malformed(format!("tbs certificate: {e}")))?;
            tbs
        }
    };
    let mut names = Vec::new();
    for cn in tbs.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            names.push(s.to_owned());
        }
        if names.len() >= MAX_NAMES_PER_CERT {
            break;
        }
    }
    if let Ok(Some(san)) = tbs.subject_alternative_name() {
        for gn in &san.value.general_names {
            if names.len() >= MAX_NAMES_PER_CERT {
                break;
            }
            if let GeneralName::DNSName(s) = gn {
                names.push((*s).to_owned());
            }
        }
    }
    let mut out: Vec<String> = names
        .into_iter()
        .map(|n| {
            let n = n.trim().to_ascii_lowercase();
            n.strip_prefix("*.")
                .unwrap_or(&n)
                .trim_end_matches('.')
                .to_owned()
        })
        .filter(|n| !n.is_empty() && n.len() <= 253)
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

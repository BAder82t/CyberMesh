//! DNS names from logged certificates.

use x509_parser::prelude::*;

use crate::CtError;
use crate::tile::{Entry, EntryKind};

/// Upper bound on names taken from one certificate (bounds work on hostile certificates).
pub const MAX_NAMES_PER_CERT: usize = 1000;

/// Subject common names and SAN `dNSName`s, lowercased, wildcard prefix and trailing dot
/// removed, sorted and de-duplicated. Names are *not* validated here.
pub fn certificate_names(entry: &Entry) -> Result<Vec<String>, CtError> {
    let mut out: Vec<String> = certificate_dns_names(entry)?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    out.dedup();
    Ok(out)
}

/// As [`certificate_names`], with whether each name was listed as a wildcard (`*.name`).
/// Sorted by (name, wildcard) and de-duplicated, so a name listed both ways appears twice.
pub fn certificate_dns_names(entry: &Entry) -> Result<Vec<(String, bool)>, CtError> {
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
    let mut out: Vec<(String, bool)> = names
        .into_iter()
        .map(|n| {
            let n = n.trim().to_ascii_lowercase();
            let (base, wildcard) = n
                .strip_prefix("*.")
                .map_or((n.as_str(), false), |b| (b, true));
            (base.trim_end_matches('.').to_owned(), wildcard)
        })
        .filter(|(n, _)| !n.is_empty() && n.len() <= 253)
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

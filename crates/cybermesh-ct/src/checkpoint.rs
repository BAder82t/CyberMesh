//! Checkpoints (C2SP `tlog-checkpoint` signed notes).
//!
//! Only the note body (origin, tree size, root hash) is parsed. Signatures (RFC 6962 ECDSA
//! note signatures) are not verified in this version; see `docs/roadmap.md`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::CtError;

/// A parsed checkpoint body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
}

impl Checkpoint {
    /// Parses the note text. Requires the three mandatory lines and a blank line before
    /// signatures.
    pub fn parse(text: &str) -> Result<Self, CtError> {
        if text.len() > 64 * 1024 {
            return Err(CtError::TooLarge);
        }
        let mut lines = text.split('\n');
        let origin = lines
            .next()
            .filter(|l| !l.is_empty())
            .ok_or_else(|| CtError::Malformed("origin".into()))?;
        let size_line = lines
            .next()
            .ok_or_else(|| CtError::Malformed("size".into()))?;
        if size_line.is_empty()
            || !size_line.bytes().all(|b| b.is_ascii_digit())
            || (size_line.len() > 1 && size_line.starts_with('0'))
        {
            return Err(CtError::Malformed("tree size".into()));
        }
        let size: u64 = size_line
            .parse()
            .map_err(|_| CtError::Malformed("tree size".into()))?;
        let root_line = lines
            .next()
            .ok_or_else(|| CtError::Malformed("root".into()))?;
        let root_bytes = B64
            .decode(root_line)
            .map_err(|_| CtError::Malformed("root hash".into()))?;
        let root: [u8; 32] = root_bytes
            .try_into()
            .map_err(|_| CtError::Malformed("root hash length".into()))?;
        Ok(Self {
            origin: origin.to_owned(),
            size,
            root,
        })
    }

    /// Number of full data tiles.
    #[must_use]
    pub fn full_tiles(&self) -> u64 {
        self.size / 256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_spec_example() {
        let t = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n";
        let c = Checkpoint::parse(t).unwrap();
        assert_eq!(c.origin, "example.com/behind-the-sofa");
        assert_eq!(c.size, 20_852_163);
        assert_eq!(c.full_tiles(), 81_453);
        for bad in ["", "o\n012\nAAAA\n", "o\n12\nnot-base64\n", "o\nx\n\n"] {
            assert!(Checkpoint::parse(bad).is_err(), "{bad:?}");
        }
    }
}

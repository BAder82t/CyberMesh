/// The security profiles of the Trust Fabric transport. Only one is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SecurityProfile {
    /// Standard computational security. Not implemented here; CyberMesh's existing transport
    /// (libp2p Noise) provides it and its protection is never counted towards the other profile.
    Standard = 1,
    /// Post-quantum computational security. Not implemented.
    PostQuantum = 2,
    /// Information-theoretic security from pre-provisioned secret pools. The only profile
    /// implemented.
    InformationTheoretic = 3,
}

//! Hash algorithms for HashML-DSA and HashSLH-DSA pre-hash mode.
//!
//! Each variant identifies a hash function used in pre-hash signing
//! per FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), and provides the
//! DER-encoded OID bytes needed for the pre-hash domain prefix.

/// Hash algorithm for HashML-DSA / HashSLH-DSA pre-hash signing.
///
/// Each variant maps to a NIST-defined hash algorithm and can produce
/// the DER-encoded OID required in the pre-hash domain prefix per
/// FIPS 204/205 Section 10.2.
///
/// All OIDs are under the NIST hash algorithm arc
/// `2.16.840.1.101.3.4.2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE-128.
    Shake128,
    /// SHAKE-256.
    Shake256,
}

impl HashAlgorithm {
    /// Return the DER-encoded OID bytes (tag + length + value) for this hash algorithm.
    ///
    /// All OIDs share the prefix `06 09` (OID tag, 9-byte value)
    /// followed by the NIST hash algorithm suffix.
    /// The last byte identifies the specific hash algorithm within the
    /// `2.16.840.1.101.3.4.2` OID tree.
    #[must_use]
    pub const fn der_bytes(&self) -> &'static [u8] {
        match self {
            // 2.16.840.1.101.3.4.2.4
            Self::Sha224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
            ],
            // 2.16.840.1.101.3.4.2.1
            Self::Sha256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            // 2.16.840.1.101.3.4.2.2
            Self::Sha384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            // 2.16.840.1.101.3.4.2.3
            Self::Sha512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
            // 2.16.840.1.101.3.4.2.5
            Self::Sha512_224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
            ],
            // 2.16.840.1.101.3.4.2.6
            Self::Sha512_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
            ],
            // 2.16.840.1.101.3.4.2.7
            Self::Sha3_224 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
            ],
            // 2.16.840.1.101.3.4.2.8
            Self::Sha3_256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
            ],
            // 2.16.840.1.101.3.4.2.9
            Self::Sha3_384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
            ],
            // 2.16.840.1.101.3.4.2.10
            Self::Sha3_512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
            ],
            // 2.16.840.1.101.3.4.2.11
            Self::Shake128 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b,
            ],
            // 2.16.840.1.101.3.4.2.12
            Self::Shake256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c,
            ],
        }
    }
}

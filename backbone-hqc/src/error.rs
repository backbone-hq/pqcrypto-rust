//! HQC error types.

use backbone_pqcrypto_internals::define_error;

define_error! {
    /// Errors that can occur during HQC key generation, encapsulation, or decapsulation.
    Error;
    /// Public key has wrong length.
    InvalidKeyLength => "invalid public key length",
    /// Secret key has wrong length.
    InvalidSecretKeyLength => "invalid secret key length",
    /// Ciphertext has wrong length.
    InvalidCiphertextLength => "invalid ciphertext length",
    /// Seed has wrong length.
    InvalidSeedLength => "invalid seed length",
    /// Decapsulation failed (re-encryption mismatch).
    DecapsulationFailed => "decapsulation failed",
    /// Random number generation failed.
    RngFailure => "random number generation failed",
}

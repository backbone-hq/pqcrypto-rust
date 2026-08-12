//! McEliece KEM error types.

use backbone_pqcrypto_internals::define_error;

define_error! {
    /// McEliece KEM errors.
    Error;
    /// Key generation failed (e.g. irreducible polynomial not found).
    KeygenFailed => "key generation failed",
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

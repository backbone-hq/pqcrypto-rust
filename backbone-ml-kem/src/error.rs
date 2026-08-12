//! ML-KEM error types.

use backbone_pqcrypto_internals::define_error;

define_error! {
    /// Errors for ML-KEM operations.
    Error;
    /// Invalid key length.
    InvalidKeyLength => "invalid public key length",
    /// Invalid public key encoding.
    InvalidPublicKey => "invalid public key",
    /// Invalid secret key length.
    InvalidSecretKeyLength => "invalid secret key length",
    /// Invalid secret key contents.
    InvalidSecretKey => "invalid secret key",
    /// Invalid ciphertext length.
    InvalidCiphertextLength => "invalid ciphertext length",
    /// Invalid seed length.
    InvalidSeedLength => "invalid seed length",
    /// RNG failure (system randomness unavailable).
    RngFailure => "random number generation failed",
}

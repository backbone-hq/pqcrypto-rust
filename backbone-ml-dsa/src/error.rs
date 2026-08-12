//! ML-DSA error types.

use backbone_pqcrypto_internals::define_error;

define_error! {
    /// ML-DSA signature errors.
    Error;
    /// Signature verification failed.
    InvalidSignature => "invalid signature",
    /// Signing failed after exhausting rejection sampling retries.
    SigningFailed => "signing failed (rejection sampling exhausted)",
    /// RNG failure (getrandom failure).
    RngFailure => "random number generation failed",
    /// Invalid public key length.
    InvalidKeyLength => "invalid public key length",
    /// Invalid secret key length.
    InvalidSecretKeyLength => "invalid secret key length",
    /// Invalid signature length.
    InvalidSignatureLength => "invalid signature length",
    /// Invalid seed length.
    InvalidSeedLength => "invalid seed length",
    /// Invalid context length.
    InvalidContextLength => "invalid context length",
    /// Invalid message length.
    InvalidMessageLength => "invalid message length",
}

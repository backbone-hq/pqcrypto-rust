//! SPHINCS+ signature error types.

use backbone_pqcrypto_internals::define_error;

define_error! {
    /// SPHINCS+ signature errors.
    Error;
    /// Signature verification failed.
    InvalidSignature => "invalid signature",
    /// Signing failed after exhausting rejection sampling retries.
    SigningFailed => "signing failed (rejection sampling exhausted)",
    /// RNG failure (getrandom failure).
    RngFailure => "random number generation failed",
    /// The public key has an invalid length.
    InvalidKeyLength => "invalid public key length",
    /// The secret key has an invalid length.
    InvalidSecretKeyLength => "invalid secret key length",
    /// The signature has an invalid length.
    InvalidSignatureLength => "invalid signature length",
    /// The supplied seed has an invalid length.
    InvalidSeedLength => "invalid seed length",
    /// The supplied context is too long for the FIPS domain separator.
    InvalidContextLength => "invalid context length",
    /// Internal invariant failure (address serialization or PRF setup).
    Internal => "internal invariant failure",
}

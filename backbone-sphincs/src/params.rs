//! Concrete SPHINCS+ parameter sets.
//!
//! Each variant is a type alias for a hash-suite parameterization.
//! Re-exported here so the `define_variant!` macro can reference `$crate::params::*`.

pub use crate::sphincs::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};

use crate::sphincs::Hash;

/// Helper trait: provides `N`, `PK_BYTES`, `SK_BYTES`, `SIG_BYTES`, `SEED_BYTES`
/// as `usize` constants.
pub trait ConstParams {
    /// Security parameter: hash output length in bytes (16, 24, or 32).
    const N: usize;
    /// Public key size in bytes.
    const PK_BYTES: usize;
    /// Secret key size in bytes.
    const SK_BYTES: usize;
    /// Signature size in bytes.
    const SIG_BYTES: usize;
    /// Length of the pk_seed / sk_seed values in bytes.
    const SEED_BYTES: usize;
    /// WOTS+ signature size in bytes.
    const WOTS_BYTES: usize;
    /// FORS signature size in bytes.
    const FORS_BYTES: usize;
    /// FORS message digest size in bytes.
    const FORS_MSG_BYTES: usize;
}

impl<P> ConstParams for P
where
    P: Hash,
{
    const N: usize = P::N;
    const PK_BYTES: usize = P::PK_BYTES;
    const SK_BYTES: usize = P::SK_BYTES;
    const SIG_BYTES: usize = P::SIG_BYTES;
    const SEED_BYTES: usize = P::SEED_BYTES;
    const WOTS_BYTES: usize = P::WOTS_BYTES;
    const FORS_BYTES: usize = P::FORS_BYTES;
    const FORS_MSG_BYTES: usize = P::FORS_MSG_BYTES;
}

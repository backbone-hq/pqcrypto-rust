//! ML-DSA (FIPS 204) Number Theoretic Transform (NTT)
//!
//! Re-exports from the selected backend (soft or avx2).

pub(crate) use crate::backends::{inv_ntt, ntt, ntt_mul};

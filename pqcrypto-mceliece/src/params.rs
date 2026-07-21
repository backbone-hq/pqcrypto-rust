//! Per-variant parameter definitions for Classic McEliece KEM variants.
//!
//! Defines the [`Params`] trait and all 10 variant marker types with their
//! associated constants.  Helper functions (`gfmask`, `cond_bytes`, …) are
//! `const fn` so they can appear in associated-constant positions.

// ── Helper functions (const) ──────────────────────────────────────────────

/// Field mask `(1 << gfbits) - 1` for GF(2^gfbits).
#[inline]
pub(crate) const fn gfmask(gfbits: usize) -> u16 {
    (1u16 << gfbits) - 1
}

/// Conditional bytes for the Benes network: `(1 << (gfbits-4)) * (2*gfbits - 1)`.
#[inline]
pub(crate) const fn cond_bytes(gfbits: usize) -> usize {
    (1 << (gfbits - 4)) * (2 * gfbits - 1)
}

/// Public-key row size in bytes: `ceil(pk_ncols / 8)`.
#[inline]
pub(crate) const fn pk_row_bytes(pk_ncols: usize) -> usize {
    pk_ncols.div_ceil(8)
}

/// Syndrome size in bytes: `ceil(pk_nrows / 8)`.
#[inline]
pub(crate) const fn synd_bytes(pk_nrows: usize) -> usize {
    pk_nrows.div_ceil(8)
}

// ── Params trait ──────────────────────────────────────────────────────────

/// Per-variant parameter set.
///
/// Marker types implementing this trait carry compile-time constants that
/// define the McEliece variant (field size, code length, etc.).
pub trait Params {
    /// Extension degree of the binary Goppa code field GF(2^GFBITS).
    const GFBITS: usize;

    /// Code length N (number of bits in a codeword).
    const SYS_N: usize;

    /// Error-correction capacity (number of errors the code can correct).
    const SYS_T: usize;

    // Derived constants (computed from the three base values above).

    /// Number of rows in the public-key generator matrix.
    const PK_NROWS: usize = Self::SYS_T * Self::GFBITS;

    /// Number of columns in the public-key generator matrix.
    const PK_NCOLS: usize = Self::SYS_N - Self::PK_NROWS;

    /// Irreducible-polynomial bytes (`SYS_T * 2`).
    const IRR_BYTES: usize = Self::SYS_T * 2;

    /// Public-key row byte count.
    const PK_ROW_BYTES: usize = pk_row_bytes(Self::PK_NCOLS);

    /// Syndrome byte count.
    const SYND_BYTES: usize = synd_bytes(Self::PK_NROWS);

    /// Conditional bytes for the Benes network.
    const COND_BYTES: usize = cond_bytes(Self::GFBITS);

    /// Field mask for GF(2^GFBITS).
    const GFMASK: u16 = gfmask(Self::GFBITS);

    // Public-key / secret-key / ciphertext sizes (from NIST spec).

    /// Public key size in bytes.
    const PK_BYTES: usize;

    /// Secret key size in bytes.
    const SK_BYTES: usize;

    /// Ciphertext (syndrome) size in bytes.
    const CT_BYTES: usize;

    /// Shared secret size in bytes.
    const SS_BYTES: usize = 32;
}

// ── Variant definitions ───────────────────────────────────────────────────

macro_rules! define_params {
    ($(#[$attr:meta])* $name:ident, $gfbits:expr, $n:expr, $t:expr, $pk:expr, $sk:expr, $ct:expr) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Debug)]
        pub struct $name;
        impl Params for $name {
            const GFBITS: usize = $gfbits;
            const SYS_N: usize = $n;
            const SYS_T: usize = $t;
            const PK_BYTES: usize = $pk;
            const SK_BYTES: usize = $sk;
            const CT_BYTES: usize = $ct;
        }
    };
}

define_params!(
    #[doc = "`Params` implementation for McEliece 348864 (12-bit field, 3488-bit code, 64 errors)."]
    McEliece348864Params,
    12,
    3488,
    64,
    261120,
    6492,
    96
);
define_params!(
    #[doc = "`Params` implementation for McEliece 348864f (12-bit field, 3488-bit code, 64 errors, fast variant)."]
    McEliece348864fParams,
    12,
    3488,
    64,
    261120,
    6492,
    96
);
define_params!(
    #[doc = "`Params` implementation for McEliece 460896 (13-bit field, 4608-bit code, 96 errors)."]
    McEliece460896Params,
    13,
    4608,
    96,
    524160,
    13608,
    156
);
define_params!(
    #[doc = "`Params` implementation for McEliece 460896f (13-bit field, 4608-bit code, 96 errors, fast variant)."]
    McEliece460896fParams,
    13,
    4608,
    96,
    524160,
    13608,
    156
);
define_params!(
    #[doc = "`Params` implementation for McEliece 6688128 (13-bit field, 6688-bit code, 128 errors)."]
    McEliece6688128Params,
    13,
    6688,
    128,
    1044992,
    13932,
    208
);
define_params!(
    #[doc = "`Params` implementation for McEliece 6688128f (13-bit field, 6688-bit code, 128 errors, fast variant)."]
    McEliece6688128fParams,
    13,
    6688,
    128,
    1044992,
    13932,
    208
);
define_params!(
    #[doc = "`Params` implementation for McEliece 6960119 (13-bit field, 6960-bit code, 119 errors)."]
    McEliece6960119Params,
    13,
    6960,
    119,
    1047319,
    13948,
    194
);
define_params!(
    #[doc = "`Params` implementation for McEliece 6960119f (13-bit field, 6960-bit code, 119 errors, fast variant)."]
    McEliece6960119fParams,
    13,
    6960,
    119,
    1047319,
    13948,
    194
);
define_params!(
    #[doc = "`Params` implementation for McEliece 8192128 (13-bit field, 8192-bit code, 128 errors)."]
    McEliece8192128Params,
    13,
    8192,
    128,
    1357824,
    14120,
    208
);
define_params!(
    #[doc = "`Params` implementation for McEliece 8192128f (13-bit field, 8192-bit code, 128 errors, fast variant)."]
    McEliece8192128fParams,
    13,
    8192,
    128,
    1357824,
    14120,
    208
);

// ── Consistency checks (test-only) ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn check_consistency<T: Params>(
        gfbits: usize,
        sys_n: usize,
        sys_t: usize,
        pk_bytes: usize,
        sk_bytes: usize,
        ct_bytes: usize,
    ) {
        assert_eq!(T::GFBITS, gfbits);
        assert_eq!(T::SYS_N, sys_n);
        assert_eq!(T::SYS_T, sys_t);
        assert_eq!(T::PK_BYTES, pk_bytes);
        assert_eq!(T::SK_BYTES, sk_bytes);
        assert_eq!(T::CT_BYTES, ct_bytes);

        // Derived constants
        assert_eq!(T::PK_NROWS, sys_t * gfbits);
        assert_eq!(T::PK_NCOLS, sys_n - sys_t * gfbits);
        assert_eq!(T::IRR_BYTES, sys_t * 2);
        assert_eq!(T::COND_BYTES, (1 << (gfbits - 4)) * (2 * gfbits - 1));
        assert_eq!(T::GFMASK, (1u16 << gfbits) - 1);
        assert_eq!(T::SS_BYTES, 32);
    }

    #[test]
    fn test_all_variants() {
        check_consistency::<McEliece348864Params>(12, 3488, 64, 261120, 6492, 96);
        check_consistency::<McEliece348864fParams>(12, 3488, 64, 261120, 6492, 96);
        check_consistency::<McEliece460896Params>(13, 4608, 96, 524160, 13608, 156);
        check_consistency::<McEliece460896fParams>(13, 4608, 96, 524160, 13608, 156);
        check_consistency::<McEliece6688128Params>(13, 6688, 128, 1044992, 13932, 208);
        check_consistency::<McEliece6688128fParams>(13, 6688, 128, 1044992, 13932, 208);
        check_consistency::<McEliece6960119Params>(13, 6960, 119, 1047319, 13948, 194);
        check_consistency::<McEliece6960119fParams>(13, 6960, 119, 1047319, 13948, 194);
        check_consistency::<McEliece8192128Params>(13, 8192, 128, 1357824, 14120, 208);
        check_consistency::<McEliece8192128fParams>(13, 8192, 128, 1357824, 14120, 208);
    }
}

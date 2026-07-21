//! McEliece 192128f (13-bit field, 8192-bit code, 128 errors, fast variant).
//!
//! Provides `keygen`, `encaps`, `decaps`, `PublicKey`, and `SecretKey`.

use crate::core_fft::gf13_8192128;
use crate::fft_tables::v8192128f::{
    FFT_CONSTS_8192128F, FFT_POWERS_8192128F, FFT_SCALARS_2X_8192128F, FFT_SCALARS_4X_8192128F,
};
crate::define_variant!(
    Mceliece8192128F,
    gf13_8192128,
    "McEliece 8192128f",
    5,
    fft_consts = FFT_CONSTS_8192128F,
    fft_powers = FFT_SCALARS_2X_8192128F,
    fft_scalars = FFT_SCALARS_4X_8192128F,
    fft_extra = FFT_POWERS_8192128F
);

//! McEliece 6688128f (13-bit field, 6688-bit code, 128 errors, fast variant).

use crate::core_fft::gf13_6688128;
use crate::fft_tables::v6688128f::{
    FFT_CONSTS_6688128F, FFT_POWERS_6688128F, FFT_SCALARS_2X_6688128F, FFT_SCALARS_4X_6688128F,
};
crate::define_variant!(
    Mceliece6688128F,
    gf13_6688128,
    "McEliece 6688128f",
    fft_consts = FFT_CONSTS_6688128F,
    fft_powers = FFT_SCALARS_2X_6688128F,
    fft_scalars = FFT_SCALARS_4X_6688128F,
    fft_extra = FFT_POWERS_6688128F,
    fast = true
);

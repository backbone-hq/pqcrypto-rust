//! McEliece 6960119 (13-bit field, 6960-bit code, 119 errors).

use crate::core_fft::gf13_6960119;
use crate::fft_tables::v6960119::{
    FFT_CONSTS_6960119, FFT_POWERS_6960119, FFT_SCALARS_2X_6960119, FFT_SCALARS_4X_6960119,
};
crate::define_variant!(
    Mceliece6960119,
    gf13_6960119,
    "McEliece 6960119",
    fft_consts = FFT_CONSTS_6960119,
    fft_powers = FFT_SCALARS_2X_6960119,
    fft_scalars = FFT_SCALARS_4X_6960119,
    fft_extra = FFT_POWERS_6960119
);

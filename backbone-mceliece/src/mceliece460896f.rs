//! McEliece 460896f (13-bit field, 4608-bit code, 96 errors, fast variant).

use crate::core_fft::gf13_460896;
use crate::fft_tables::v460896f::{
    FFT_CONSTS_460896F, FFT_POWERS_460896F, FFT_SCALARS_2X_460896F, FFT_SCALARS_4X_460896F,
};
crate::define_variant!(
    Mceliece460896F,
    gf13_460896,
    "McEliece 460896f",
    1,
    fft_consts = FFT_CONSTS_460896F,
    fft_powers = FFT_SCALARS_2X_460896F,
    fft_scalars = FFT_SCALARS_4X_460896F,
    fft_extra = FFT_POWERS_460896F
);

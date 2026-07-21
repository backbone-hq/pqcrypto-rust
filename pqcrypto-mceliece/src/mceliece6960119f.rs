//! McEliece 960119f (13-bit field, 6960-bit code, 119 errors, fast variant).
//!
//! Provides `keygen`, `encaps`, `decaps`, `PublicKey`, and `SecretKey`.

use crate::core_fft::gf13_6960119;
use crate::fft_tables::v6960119f::{
    FFT_CONSTS_6960119F, FFT_POWERS_6960119F, FFT_SCALARS_2X_6960119F, FFT_SCALARS_4X_6960119F,
};
crate::define_variant!(
    Mceliece6960119F,
    gf13_6960119,
    "McEliece 6960119f",
    5,
    fft_consts = FFT_CONSTS_6960119F,
    fft_powers = FFT_SCALARS_2X_6960119F,
    fft_scalars = FFT_SCALARS_4X_6960119F,
    fft_extra = FFT_POWERS_6960119F
);

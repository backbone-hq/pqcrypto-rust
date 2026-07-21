//! McEliece 6688128 (13-bit field, 6688-bit code, 128 errors).
//!
//! Provides `keygen`, `encaps`, `decaps`, `PublicKey`, and `SecretKey`.

//! McEliece 6688128 variant (13-bit field, 6688-bit code, 128 errors).
use crate::core_fft::gf13_6688128;
use crate::fft_tables::v6688128::{
    FFT_CONSTS_6688128, FFT_POWERS_6688128, FFT_SCALARS_2X_6688128, FFT_SCALARS_4X_6688128,
};
crate::define_variant!(
    Mceliece6688128,
    gf13_6688128,
    "McEliece 6688128",
    "3",
    fft_consts = FFT_CONSTS_6688128,
    fft_powers = FFT_SCALARS_2X_6688128,
    fft_scalars = FFT_SCALARS_4X_6688128,
    fft_extra = FFT_POWERS_6688128
);

//! McEliece 460896 (13-bit field, 4608-bit code, 96 errors).
//!
//! Provides `keygen`, `encaps`, `decaps`, `PublicKey`, and `SecretKey`.

//! McEliece 460896 variant (13-bit field, 4608-bit code, 96 errors).
use crate::core_fft::gf13_460896;
use crate::fft_tables::v460896::{
    FFT_CONSTS_460896, FFT_POWERS_460896, FFT_SCALARS_2X_460896, FFT_SCALARS_4X_460896,
};
crate::define_variant!(
    McEliece460896,
    gf13_460896,
    "McEliece 460896",
    "1",
    fft_consts = FFT_CONSTS_460896,
    fft_powers = FFT_SCALARS_2X_460896,
    fft_scalars = FFT_SCALARS_4X_460896,
    fft_extra = FFT_POWERS_460896
);

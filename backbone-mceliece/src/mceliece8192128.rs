//! McEliece 8192128 (13-bit field, 8192-bit code, 128 errors).
//!
//! Provides `keygen`, `encaps`, `decaps`, `PublicKey`, and `SecretKey`.

//! McEliece 8192128 variant (13-bit field, 8192-bit code, 128 errors).
use crate::core_fft::gf13_8192128;
use crate::fft_tables::v8192128::{
    FFT_CONSTS_8192128, FFT_POWERS_8192128, FFT_SCALARS_2X_8192128, FFT_SCALARS_4X_8192128,
};
crate::define_variant!(
    Mceliece8192128,
    gf13_8192128,
    "McEliece 8192128",
    "5",
    fft_consts = FFT_CONSTS_8192128,
    fft_powers = FFT_SCALARS_2X_8192128,
    fft_scalars = FFT_SCALARS_4X_8192128,
    fft_extra = FFT_POWERS_8192128
);

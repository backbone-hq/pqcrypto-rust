//! McEliece 348864 (12-bit field, 3488-bit code, 64 errors).
//!
//! Provides `keygen`, `encaps`, `decaps`, `PublicKey`, and `SecretKey`.

//! McEliece 348864 variant (12-bit field, 3488-bit code, 64 errors).
use crate::core_fft::gf12;
use crate::fft_tables::v348864::{FFT_CONSTS_348864, FFT_POWERS_348864, FFT_SCALARS_348864};
crate::define_variant!(
    McEliece348864,
    gf12,
    "McEliece 348864",
    "1",
    fft_consts = FFT_CONSTS_348864,
    fft_powers = FFT_POWERS_348864,
    fft_scalars = FFT_SCALARS_348864
);

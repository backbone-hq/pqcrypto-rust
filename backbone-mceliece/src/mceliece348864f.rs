//! McEliece 348864f (12-bit field, 3488-bit code, 64 errors, fast variant).

use crate::core_fft::gf12;
use crate::fft_tables::v348864f::{FFT_CONSTS_348864F, FFT_POWERS_348864F, FFT_SCALARS_348864F};
crate::define_variant!(
    McEliece348864f,
    gf12,
    "McEliece 348864f",
    fft_consts = FFT_CONSTS_348864F,
    fft_powers = FFT_POWERS_348864F,
    fft_scalars = FFT_SCALARS_348864F,
    fast = true
);

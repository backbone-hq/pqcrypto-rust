//! Pre-computed FFT table constants for all Classic McEliece parameter sets.
//!
//! Each submodule corresponds to one variant and defines its tables with
//! variant-qualified names (e.g. `FFT_CONSTS_348864`).

pub(crate) mod v348864;
pub(crate) mod v348864f;
pub(crate) mod v460896;
pub(crate) mod v460896f;
pub(crate) mod v6688128;
pub(crate) mod v6688128f;
pub(crate) mod v6960119;
pub(crate) mod v6960119f;
pub(crate) mod v8192128;
pub(crate) mod v8192128f;

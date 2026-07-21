/// SPHINCS+ algorithm parameter interface.
///
/// Each variant (e.g. [`Shake128s`], [`Sha2_256f`]) implements this trait
/// with the concrete constants prescribed by FIPS 205.
pub trait Params {
    /// Security parameter *n* (bytes): the size of hash outputs and keys.
    const N: usize;
    /// Total height of the hyper-tree.
    const H: usize;
    /// Number of layers in the hyper-tree.
    const D: usize;
    /// Height of each individual Merkle tree (`H / D`).
    const TREE_H: usize;
    /// FORS tree height (log2 of the number of leaves per FORS tree).
    const LOG_T: usize;
    /// Number of FORS trees.
    const K: usize;
    /// WOTS+ chain length (number of private-key elements).
    const WOTS_LEN: usize;
    /// WOTS+ signature size in bytes.
    const WOTS_BYTES: usize;
    /// FORS message digest size in bytes.
    const FORS_MSG_BYTES: usize;
    /// FORS signature size in bytes.
    const FORS_BYTES: usize;
    /// Full SPHINCS+ signature size in bytes.
    const SIG_BYTES: usize;
    /// Public key size in bytes.
    const PK_BYTES: usize;
    /// Secret key size in bytes.
    const SK_BYTES: usize;
    /// Seed size in bytes (used for deterministic key generation).
    const SEED_BYTES: usize;
}

macro_rules! impl_params {
    ($name:ident, $n:expr, $h:expr, $d:expr, $log_t:expr, $k:expr) => {
        impl Params for $name {
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const TREE_H: usize = $h / $d;
            const LOG_T: usize = $log_t;
            const K: usize = $k;
            const WOTS_LEN: usize = 2 * $n + 3;
            const WOTS_BYTES: usize = (2 * $n + 3) * $n;
            const FORS_MSG_BYTES: usize = (($log_t * $k) as usize).div_ceil(8);
            const FORS_BYTES: usize = ($log_t + 1) * $k * $n;
            const SIG_BYTES: usize =
                $n + (($log_t + 1) * $k * $n) + $d * ((2 * $n + 3) * $n) + $h * $n;
            const PK_BYTES: usize = 2 * $n;
            const SK_BYTES: usize = 4 * $n;
            const SEED_BYTES: usize = 3 * $n;
        }
    };
}

macro_rules! define_variant {
    ($name:ident, $n:expr, $h:expr, $d:expr, $log_t:expr, $k:expr) => {
        #[doc = concat!("SPHINCS+ ", stringify!($name), " parameter singleton.")]
        #[derive(Copy, Clone, Debug)]
        pub struct $name;
        impl_params!($name, $n, $h, $d, $log_t, $k);
    };
}

define_variant!(Shake128s, 16, 63, 7, 12, 14);
define_variant!(Shake128f, 16, 66, 22, 6, 33);
define_variant!(Shake192s, 24, 63, 7, 14, 17);
define_variant!(Shake192f, 24, 66, 22, 8, 33);
define_variant!(Shake256s, 32, 64, 8, 14, 22);
define_variant!(Shake256f, 32, 68, 17, 9, 35);

define_variant!(Sha2_128s, 16, 63, 7, 12, 14);
define_variant!(Sha2_128f, 16, 66, 22, 6, 33);
define_variant!(Sha2_192s, 24, 63, 7, 14, 17);
define_variant!(Sha2_192f, 24, 66, 22, 8, 33);
define_variant!(Sha2_256s, 32, 64, 8, 14, 22);
define_variant!(Sha2_256f, 32, 68, 17, 9, 35);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_shake128s() {
        assert_eq!(<Shake128s as Params>::SIG_BYTES, 7856);
        assert_eq!(<Shake128s as Params>::PK_BYTES, 32);
        assert_eq!(<Shake128s as Params>::SK_BYTES, 64);
        assert_eq!(<Shake128s as Params>::SEED_BYTES, 48);
        assert_eq!(<Shake128s as Params>::FORS_MSG_BYTES, 21);
    }

    #[test]
    fn test_params_shake128f() {
        assert_eq!(<Shake128f as Params>::SIG_BYTES, 17088);
        assert_eq!(<Shake128f as Params>::PK_BYTES, 32);
        assert_eq!(<Shake128f as Params>::SK_BYTES, 64);
        assert_eq!(<Shake128f as Params>::SEED_BYTES, 48);
    }

    #[test]
    fn test_params_shake192s() {
        assert_eq!(<Shake192s as Params>::SIG_BYTES, 16224);
        assert_eq!(<Shake192s as Params>::PK_BYTES, 48);
        assert_eq!(<Shake192s as Params>::SK_BYTES, 96);
        assert_eq!(<Shake192s as Params>::SEED_BYTES, 72);
    }

    #[test]
    fn test_params_shake192f() {
        assert_eq!(<Shake192f as Params>::SIG_BYTES, 35664);
        assert_eq!(<Shake192f as Params>::PK_BYTES, 48);
        assert_eq!(<Shake192f as Params>::SK_BYTES, 96);
    }

    #[test]
    fn test_params_shake256s() {
        assert_eq!(<Shake256s as Params>::SIG_BYTES, 29792);
        assert_eq!(<Shake256s as Params>::PK_BYTES, 64);
        assert_eq!(<Shake256s as Params>::SK_BYTES, 128);
        assert_eq!(<Shake256s as Params>::SEED_BYTES, 96);
    }

    #[test]
    fn test_params_shake256f() {
        assert_eq!(<Shake256f as Params>::SIG_BYTES, 49856);
        assert_eq!(<Shake256f as Params>::PK_BYTES, 64);
        assert_eq!(<Shake256f as Params>::SK_BYTES, 128);
    }

    #[test]
    fn test_params_sha2_128s() {
        assert_eq!(<Sha2_128s as Params>::SIG_BYTES, 7856);
        assert_eq!(<Sha2_128s as Params>::PK_BYTES, 32);
        assert_eq!(<Sha2_128s as Params>::SK_BYTES, 64);
    }

    #[test]
    fn test_params_sha2_128f() {
        assert_eq!(<Sha2_128f as Params>::SIG_BYTES, 17088);
        assert_eq!(<Sha2_128f as Params>::PK_BYTES, 32);
        assert_eq!(<Sha2_128f as Params>::SK_BYTES, 64);
    }

    #[test]
    fn test_params_sha2_192s() {
        assert_eq!(<Sha2_192s as Params>::SIG_BYTES, 16224);
        assert_eq!(<Sha2_192s as Params>::PK_BYTES, 48);
        assert_eq!(<Sha2_192s as Params>::SK_BYTES, 96);
    }

    #[test]
    fn test_params_sha2_192f() {
        assert_eq!(<Sha2_192f as Params>::SIG_BYTES, 35664);
        assert_eq!(<Sha2_192f as Params>::PK_BYTES, 48);
        assert_eq!(<Sha2_192f as Params>::SK_BYTES, 96);
    }

    #[test]
    fn test_params_sha2_256s() {
        assert_eq!(<Sha2_256s as Params>::SIG_BYTES, 29792);
        assert_eq!(<Sha2_256s as Params>::PK_BYTES, 64);
        assert_eq!(<Sha2_256s as Params>::SK_BYTES, 128);
    }

    #[test]
    fn test_params_sha2_256f() {
        assert_eq!(<Sha2_256f as Params>::SIG_BYTES, 49856);
        assert_eq!(<Sha2_256f as Params>::PK_BYTES, 64);
        assert_eq!(<Sha2_256f as Params>::SK_BYTES, 128);
    }
}

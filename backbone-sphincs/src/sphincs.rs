#![allow(clippy::cast_possible_truncation)]
// All casts in this module operate on bounded values (byte/limb extraction, loop counters).
//! SLH-DSA (SPHINCS+) internal algorithm implementation.
//!
//! All internal types and functions consolidated into a single module,
//! mirroring the pattern used by `backbone-ml-dsa/src/sign.rs`.

use alloc::vec::Vec;
use backbone_pqcrypto_internals::secret::SecretVec;
use core::fmt::Debug;

use digest::{Digest, KeyInit, Update};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use shake::digest::{ExtendableOutput, XofReader};
use shake::Shake256;

use zerocopy::byteorder::big_endian::{U32 as BeU32, U64 as BeU64};
use zerocopy::{Immutable, IntoBytes};

use backbone_pqcrypto_internals::oid::HashAlgorithm;

/// FIPS 205 §10.2.2 (HashSLH-DSA): compute the pre-hash `PH(M)` of the content
/// to be signed. Output lengths follow the spec — SHAKE-128 ⇒ 256 bits,
/// SHAKE-256 ⇒ 512 bits; the SHA-2/SHA-3 functions use their natural digest
/// lengths.
pub(crate) fn prehash_message(alg: HashAlgorithm, msg: &[u8]) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput as _, Update as _, XofReader as _};
    use sha3::Digest as _;
    match alg {
        HashAlgorithm::Sha224 => sha2::Sha224::digest(msg).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(msg).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(msg).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(msg).to_vec(),
        HashAlgorithm::Sha512_224 => sha2::Sha512_224::digest(msg).to_vec(),
        HashAlgorithm::Sha512_256 => sha2::Sha512_256::digest(msg).to_vec(),
        HashAlgorithm::Sha3_224 => sha3::Sha3_224::digest(msg).to_vec(),
        HashAlgorithm::Sha3_256 => sha3::Sha3_256::digest(msg).to_vec(),
        HashAlgorithm::Sha3_384 => sha3::Sha3_384::digest(msg).to_vec(),
        HashAlgorithm::Sha3_512 => sha3::Sha3_512::digest(msg).to_vec(),
        HashAlgorithm::Shake128 => {
            let mut out = [0u8; 32];
            let mut h = sha3::Shake128::default();
            h.update(msg);
            let mut xof = h.finalize_xof();
            xof.read(&mut out);
            out.to_vec()
        }
        HashAlgorithm::Shake256 => {
            let mut out = [0u8; 64];
            let mut h = sha3::Shake256::default();
            h.update(msg);
            let mut xof = h.finalize_xof();
            xof.read(&mut out);
            out.to_vec()
        }
    }
}

use crate::error::Error;

// -----------------------------------------------------------------------
// Address types (FIPS-205 Section 4.2)
// -----------------------------------------------------------------------

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct WotsHash {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    pub key_pair_adrs: BeU32,
    pub chain_adrs: BeU32,
    pub hash_adrs: BeU32,
}
impl AsRef<[u8]> for WotsHash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl Default for WotsHash {
    fn default() -> Self {
        Self {
            layer_adrs: BeU32::new(0),
            tree_adrs_high: BeU32::new(0),
            tree_adrs_low: BeU64::new(0),
            type_const: BeU32::new(0),
            key_pair_adrs: BeU32::new(0),
            chain_adrs: BeU32::new(0),
            hash_adrs: BeU32::new(0),
        }
    }
}

impl WotsHash {
    fn prf_adrs(&self) -> WotsPrf {
        WotsPrf {
            layer_adrs: self.layer_adrs,
            tree_adrs_high: self.tree_adrs_high,
            tree_adrs_low: self.tree_adrs_low,
            type_const: BeU32::new(5),
            key_pair_adrs: self.key_pair_adrs,
            chain_adrs: BeU32::new(0),
            hash_adrs: BeU32::new(0),
        }
    }
    fn pk_adrs(&self) -> WotsPk {
        WotsPk {
            layer_adrs: self.layer_adrs,
            tree_adrs_high: self.tree_adrs_high,
            tree_adrs_low: self.tree_adrs_low,
            type_const: BeU32::new(1),
            key_pair_adrs: self.key_pair_adrs,
            padding: BeU64::new(0),
        }
    }
    fn tree_adrs(&self) -> HashTree {
        HashTree {
            layer_adrs: self.layer_adrs,
            tree_adrs_high: self.tree_adrs_high,
            tree_adrs_low: self.tree_adrs_low,
            type_const: BeU32::new(2),
            padding: BeU32::new(0),
            tree_height: BeU32::new(0),
            tree_index: BeU32::new(0),
        }
    }
}

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct WotsPk {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    pub key_pair_adrs: BeU32,
    padding: BeU64,
}
impl AsRef<[u8]> for WotsPk {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct HashTree {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    padding: BeU32,
    pub tree_height: BeU32,
    pub tree_index: BeU32,
}
impl AsRef<[u8]> for HashTree {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct ForsTree {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    pub key_pair_adrs: BeU32,
    pub tree_height: BeU32,
    pub tree_index: BeU32,
}
impl AsRef<[u8]> for ForsTree {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ForsTree {
    pub(crate) fn new(idx_tree: u64, idx_leaf: u32) -> Self {
        Self {
            layer_adrs: BeU32::new(0),
            tree_adrs_high: BeU32::new(0),
            tree_adrs_low: BeU64::new(idx_tree),
            type_const: BeU32::new(3),
            key_pair_adrs: BeU32::new(idx_leaf),
            tree_height: BeU32::new(0),
            tree_index: BeU32::new(0),
        }
    }
    pub(crate) fn prf_adrs(&self) -> ForsPrf {
        ForsPrf {
            layer_adrs: BeU32::new(0),
            tree_adrs_high: self.tree_adrs_high,
            tree_adrs_low: self.tree_adrs_low,
            type_const: BeU32::new(6),
            key_pair_adrs: self.key_pair_adrs,
            tree_height: BeU32::new(0),
            tree_index: BeU32::new(0),
        }
    }
    fn fors_roots(&self) -> ForsRoots {
        ForsRoots {
            layer_adrs: self.layer_adrs,
            tree_adrs_high: self.tree_adrs_high,
            tree_adrs_low: self.tree_adrs_low,
            type_const: BeU32::new(4),
            key_pair_adrs: self.key_pair_adrs,
            padding: BeU64::new(0),
        }
    }
}

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct ForsRoots {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    pub key_pair_adrs: BeU32,
    padding: BeU64,
}
impl AsRef<[u8]> for ForsRoots {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct WotsPrf {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    pub key_pair_adrs: BeU32,
    pub chain_adrs: BeU32,
    pub hash_adrs: BeU32,
}
impl AsRef<[u8]> for WotsPrf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct ForsPrf {
    pub layer_adrs: BeU32,
    pub tree_adrs_high: BeU32,
    pub tree_adrs_low: BeU64,
    type_const: BeU32,
    pub key_pair_adrs: BeU32,
    pub tree_height: BeU32,
    pub tree_index: BeU32,
}
impl AsRef<[u8]> for ForsPrf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Serialize an SLH-DSA address to its fixed 32-byte representation.
///
/// All address types are `#[repr(C)]` structs of exactly 32 bytes, so this
/// conversion is an internal invariant; failures map to [`Error::Internal`].
fn adrs_bytes<A: AsRef<[u8]>>(a: &A) -> Result<&[u8; 32], Error> {
    a.as_ref().try_into().map_err(|_| Error::Internal)
}

// -----------------------------------------------------------------------
// Hash trait — the core hash interface for SLH-DSA
// -----------------------------------------------------------------------

pub trait Hash: Sized {
    // Serialized byte lengths
    const PK_BYTES: usize;
    const SK_BYTES: usize;
    const SIG_BYTES: usize;
    const SEED_BYTES: usize;
    const WOTS_BYTES: usize;
    const FORS_BYTES: usize;
    const FORS_MSG_BYTES: usize;
    // Algorithm parameters
    const N: usize;
    const H: usize; // total hypertree height
    const D: usize; // hypertree layers
    const H_PRIME: usize; // subtree height (= H / D)
    const K: usize; // FORS trees
    const A: usize; // FORS tree height (LOG_T)
    const MD: usize; // FORS message digest bytes
    const WOTS_LEN: usize; // WOTS+ chain length (= 2*N + 3)

    fn prf_addr(out: &mut [u8], pub_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32]);
    fn thash(out: &mut [u8], in_: &[u8], inblocks: usize, pub_seed: &[u8], addr: &[u8; 32]);
    fn gen_message_random(
        r: &mut [u8],
        sk_prf: &[u8],
        optrand: &[u8],
        msg: &[u8],
    ) -> Result<(), Error>;
    fn hash_message(
        digest: &mut [u8],
        tree: &mut u64,
        leaf_idx: &mut u32,
        r: &[u8],
        pk: &[u8],
        msg: &[u8],
    );
}

// -----------------------------------------------------------------------
// Concrete variants
// -----------------------------------------------------------------------

/// SLH-DSA-SHAKE-128s parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Shake128s;
/// SLH-DSA-SHAKE-128f parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Shake128f;
/// SLH-DSA-SHAKE-192s parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Shake192s;
/// SLH-DSA-SHAKE-192f parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Shake192f;
/// SLH-DSA-SHAKE-256s parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Shake256s;
/// SLH-DSA-SHAKE-256f parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Shake256f;
/// SLH-DSA-SHA2-128s parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Sha2_128s;
/// SLH-DSA-SHA2-128f parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Sha2_128f;
/// SLH-DSA-SHA2-192s parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Sha2_192s;
/// SLH-DSA-SHA2-192f parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Sha2_192f;
/// SLH-DSA-SHA2-256s parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Sha2_256s;
/// SLH-DSA-SHA2-256f parameter set.
#[derive(Clone, Copy, Debug)]
pub struct Sha2_256f;

// -----------------------------------------------------------------------
// SHAKE Hash implementations
// -----------------------------------------------------------------------

macro_rules! impl_hash_shake {
    ($($name:ident: $n:expr, $h:expr, $d:expr, $hprime:expr, $k:expr, $a:expr, $md:expr, $wots_len:expr, $pk:expr, $sk:expr, $sig:expr, $seed:expr, $wots:expr, $fors:expr, $fors_msg:expr),+ $(,)?) => {
        $(impl Hash for $name {
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const H_PRIME: usize = $hprime;
            const K: usize = $k;
            const A: usize = $a;
            const MD: usize = $md;
            const WOTS_LEN: usize = $wots_len;
            const PK_BYTES: usize = $pk;
            const SK_BYTES: usize = $sk;
            const SIG_BYTES: usize = $sig;
            const SEED_BYTES: usize = $seed;
            const WOTS_BYTES: usize = $wots;
            const FORS_BYTES: usize = $fors;
            const FORS_MSG_BYTES: usize = $fors_msg;

            fn prf_addr(out: &mut [u8], pub_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32]) {
                let mut shake = Shake256::default();
                Update::update(&mut shake, pub_seed);
                Update::update(&mut shake, addr);
                Update::update(&mut shake, sk_seed);
                let mut xof = shake.finalize_xof();
                xof.read(out);
            }

            fn thash(out: &mut [u8], in_: &[u8], _inblocks: usize, pub_seed: &[u8], addr: &[u8; 32]) {
                let mut shake = Shake256::default();
                Update::update(&mut shake, pub_seed);
                Update::update(&mut shake, addr);
                Update::update(&mut shake, in_);
                let mut xof = shake.finalize_xof();
                xof.read(out);
            }

            fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]) -> Result<(), Error> {
                let mut shake = Shake256::default();
                Update::update(&mut shake, sk_prf);
                Update::update(&mut shake, optrand);
                Update::update(&mut shake, msg);
                let mut xof = shake.finalize_xof();
                xof.read(r);
                Ok(())
            }

            fn hash_message(digest: &mut [u8], tree: &mut u64, leaf_idx: &mut u32, r: &[u8], pk: &[u8], msg: &[u8]) {
                let fors_msg_bytes = Self::MD;
                let tree_bits = Self::H - Self::H_PRIME;
                let tree_bytes = tree_bits.div_ceil(8);
                let leaf_bits = Self::H_PRIME;
                let leaf_bytes = leaf_bits.div_ceil(8);
                let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;

                let mut buf = alloc::vec![0u8; dgst_bytes];
                let mut shake = Shake256::default();
                Update::update(&mut shake, r);
                Update::update(&mut shake, pk);
                Update::update(&mut shake, msg);
                let mut xof = shake.finalize_xof();
                xof.read(&mut buf);

                digest[..fors_msg_bytes].copy_from_slice(&buf[..fors_msg_bytes]);

                let mut tree_val = 0u64;
                for &b in &buf[fors_msg_bytes..fors_msg_bytes + tree_bytes] {
                    tree_val = (tree_val << 8) | u64::from(b);
                }
                if tree_bits < 64 {
                    *tree = tree_val & ((1u64 << tree_bits) - 1);
                } else {
                    *tree = tree_val;
                }

                let mut leaf_val = 0u32;
                for &b in &buf[fors_msg_bytes + tree_bytes..fors_msg_bytes + tree_bytes + leaf_bytes] {
                    leaf_val = (leaf_val << 8) | u32::from(b);
                }
                if leaf_bits < 32 {
                    *leaf_idx = leaf_val & ((1u32 << leaf_bits) - 1);
                } else {
                    *leaf_idx = leaf_val;
                }
            }
        })+
    };
}

impl_hash_shake!(
    Shake128s: 16, 63, 7, 9, 14, 12, 21, 35, 32, 64, 7856, 48, 560, 2912, 21,
    Shake128f: 16, 66, 22, 3, 33, 6, 25, 35, 32, 64, 17088, 48, 560, 3696, 25,
    Shake192s: 24, 63, 7, 9, 17, 14, 30, 51, 48, 96, 16224, 72, 1224, 6120, 30,
    Shake192f: 24, 66, 22, 3, 33, 8, 33, 51, 48, 96, 35664, 72, 1224, 7128, 33,
    Shake256s: 32, 64, 8, 8, 22, 14, 39, 67, 64, 128, 29792, 96, 2144, 10560, 39,
    Shake256f: 32, 68, 17, 4, 35, 9, 40, 67, 64, 128, 49856, 96, 2144, 11200, 40,
);

// -----------------------------------------------------------------------
// SHA2 Hash implementations (Security Category 1: Sha2_128s, Sha2_128f)
// -----------------------------------------------------------------------

macro_rules! impl_hash_sha2_256 {
    ($($name:ident: $n:expr, $h:expr, $d:expr, $hprime:expr, $k:expr, $a:expr, $md:expr, $wots_len:expr, $pk:expr, $sk:expr, $sig:expr, $seed:expr, $wots:expr, $fors:expr, $fors_msg:expr),+ $(,)?) => {
        $(impl Hash for $name {
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const H_PRIME: usize = $hprime;
            const K: usize = $k;
            const A: usize = $a;
            const MD: usize = $md;
            const WOTS_LEN: usize = $wots_len;
            const PK_BYTES: usize = $pk;
            const SK_BYTES: usize = $sk;
            const SIG_BYTES: usize = $sig;
            const SEED_BYTES: usize = $seed;
            const WOTS_BYTES: usize = $wots;
            const FORS_BYTES: usize = $fors;
            const FORS_MSG_BYTES: usize = $fors_msg;

            fn prf_addr(out: &mut [u8], pub_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32]) {
                let n = Self::N;
                // Compressed address: ADRS[3] ∥ ADRS[8:16] ∥ ADRS[19] ∥ ADRS[20:32]
                let mut c = [0u8; 22];
                c[0] = addr[3];
                c[1..9].copy_from_slice(&addr[8..16]);
                c[9] = addr[19];
                c[10..22].copy_from_slice(&addr[20..32]);
                let mut block = [0u8; 64];
                block[..n].copy_from_slice(pub_seed);
                let mut hasher = Sha256::default();
                Update::update(&mut hasher, &block);
                Update::update(&mut hasher, &c);
                Update::update(&mut hasher, sk_seed);
                let hash = hasher.finalize();
                out.copy_from_slice(&hash[..n]);
            }

            fn thash(out: &mut [u8], in_: &[u8], inblocks: usize, pub_seed: &[u8], addr: &[u8; 32]) {
                let n = Self::N;
                // Compressed address: ADRS[3] ∥ ADRS[8:16] ∥ ADRS[19] ∥ ADRS[20:32]
                let mut c = [0u8; 22];
                c[0] = addr[3];
                c[1..9].copy_from_slice(&addr[8..16]);
                c[9] = addr[19];
                c[10..22].copy_from_slice(&addr[20..32]);
                let mut block = [0u8; 64];
                block[..n].copy_from_slice(pub_seed);
                let mut hasher = Sha256::default();
                Update::update(&mut hasher, &block);
                Update::update(&mut hasher, &c);
                Update::update(&mut hasher, &in_[..inblocks * n]);
                let hash = hasher.finalize();
                out.copy_from_slice(&hash[..n]);
            }

            fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]) -> Result<(), Error> {
                let mut mac = Hmac::<Sha256>::new_from_slice(sk_prf).map_err(|_| Error::Internal)?;
                Update::update(&mut mac, optrand);
                Update::update(&mut mac, msg);
                let result = mac.finalize().into_bytes();
                r.copy_from_slice(&result[..Self::N]);
                Ok(())
            }

            fn hash_message(digest: &mut [u8], tree: &mut u64, leaf_idx: &mut u32, r: &[u8], pk: &[u8], msg: &[u8]) {
                let n = Self::N;
                let fors_msg_bytes = Self::MD;
                let tree_bits = Self::H - Self::H_PRIME;
                let tree_bytes = tree_bits.div_ceil(8);
                let leaf_bits = Self::H_PRIME;
                let leaf_bytes = leaf_bits.div_ceil(8);
                let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;

                let mut hasher = Sha256::default();
                Update::update(&mut hasher, r);
                Update::update(&mut hasher, pk);
                Update::update(&mut hasher, msg);
                let seed_core = hasher.finalize();

                let mgf_seed_len = 2 * n + 32;
                let mut mgf_seed = SecretVec::<u8>::new(mgf_seed_len);
                mgf_seed[..n].copy_from_slice(r);
                mgf_seed[n..2 * n].copy_from_slice(&pk[..n]);
                mgf_seed[2 * n..mgf_seed_len].copy_from_slice(&seed_core);

                let mut buf = alloc::vec![0u8; dgst_bytes];
                mgf1_256(&mut buf, &mgf_seed);

                digest[..fors_msg_bytes].copy_from_slice(&buf[..fors_msg_bytes]);

                let mut tree_val = 0u64;
                for &b in &buf[fors_msg_bytes..fors_msg_bytes + tree_bytes] {
                    tree_val = (tree_val << 8) | u64::from(b);
                }
                if tree_bits < 64 {
                    *tree = tree_val & ((1u64 << tree_bits) - 1);
                } else {
                    *tree = tree_val;
                }

                let mut leaf_val = 0u32;
                for &b in &buf[fors_msg_bytes + tree_bytes..fors_msg_bytes + tree_bytes + leaf_bytes] {
                    leaf_val = (leaf_val << 8) | u32::from(b);
                }
                if leaf_bits < 32 {
                    *leaf_idx = leaf_val & ((1u32 << leaf_bits) - 1);
                } else {
                    *leaf_idx = leaf_val;
                }
            }
        })+
    };
}

impl_hash_sha2_256!(
    Sha2_128s: 16, 63, 7, 9, 14, 12, 21, 35, 32, 64, 7856, 48, 560, 2912, 21,
    Sha2_128f: 16, 66, 22, 3, 33, 6, 25, 35, 32, 64, 17088, 48, 560, 3696, 25,
);

// -----------------------------------------------------------------------
// SHA2 Hash implementations (Security Categories 3 and 5)
// -----------------------------------------------------------------------

fn mgf1_256(out: &mut [u8], seed: &[u8]) {
    let mut counter = 0u32;
    let mut offset = 0;
    while offset < out.len() {
        let mut hasher = Sha256::default();
        Update::update(&mut hasher, seed);
        Update::update(&mut hasher, &counter.to_be_bytes());
        let hash = hasher.finalize();
        let end = (offset + 32).min(out.len());
        out[offset..end].copy_from_slice(&hash[..end - offset]);
        offset += 32;
        counter += 1;
    }
}

fn mgf1_512(out: &mut [u8], seed: &[u8]) {
    let mut counter = 0u32;
    let mut offset = 0;
    while offset < out.len() {
        let mut hasher = Sha512::default();
        Update::update(&mut hasher, seed);
        Update::update(&mut hasher, &counter.to_be_bytes());
        let hash = hasher.finalize();
        let end = (offset + 64).min(out.len());
        out[offset..end].copy_from_slice(&hash[..end - offset]);
        offset += 64;
        counter += 1;
    }
}

macro_rules! impl_hash_sha2_512 {
    ($($name:ident: $n:expr, $h:expr, $d:expr, $hprime:expr, $k:expr, $a:expr, $md:expr, $wots_len:expr, $pk:expr, $sk:expr, $sig:expr, $seed:expr, $wots:expr, $fors:expr, $fors_msg:expr),+ $(,)?) => {
        $(impl Hash for $name {
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const H_PRIME: usize = $hprime;
            const K: usize = $k;
            const A: usize = $a;
            const MD: usize = $md;
            const WOTS_LEN: usize = $wots_len;
            const PK_BYTES: usize = $pk;
            const SK_BYTES: usize = $sk;
            const SIG_BYTES: usize = $sig;
            const SEED_BYTES: usize = $seed;
            const WOTS_BYTES: usize = $wots;
            const FORS_BYTES: usize = $fors;
            const FORS_MSG_BYTES: usize = $fors_msg;

            fn prf_addr(out: &mut [u8], pub_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32]) {
                let n = Self::N;
                let mut c = [0u8; 22];
                c[0] = addr[3];
                c[1..9].copy_from_slice(&addr[8..16]);
                c[9] = addr[19];
                c[10..22].copy_from_slice(&addr[20..32]);
                let mut block = [0u8; 64];
                block[..n].copy_from_slice(pub_seed);
                let mut hasher = Sha256::default();
                Update::update(&mut hasher, &block);
                Update::update(&mut hasher, &c);
                Update::update(&mut hasher, sk_seed);
                let hash = hasher.finalize();
                out.copy_from_slice(&hash[..n]);
            }

            fn thash(out: &mut [u8], in_: &[u8], inblocks: usize, pub_seed: &[u8], addr: &[u8; 32]) {
                let n = Self::N;
                // Compressed address: ADRS[3] ∥ ADRS[8:16] ∥ ADRS[19] ∥ ADRS[20:32]
                let mut c = [0u8; 22];
                c[0] = addr[3];
                c[1..9].copy_from_slice(&addr[8..16]);
                c[9] = addr[19];
                c[10..22].copy_from_slice(&addr[20..32]);
                if inblocks > 1 {
                    let mut block = [0u8; 128];
                    block[..n].copy_from_slice(pub_seed);
                    let mut hasher = Sha512::default();
                    Update::update(&mut hasher, &block);
                    Update::update(&mut hasher, &c);
                    Update::update(&mut hasher, &in_[..inblocks * n]);
                    let hash = hasher.finalize();
                    out.copy_from_slice(&hash[..n]);
                } else {
                    let mut block = [0u8; 64];
                    block[..n].copy_from_slice(pub_seed);
                    let mut hasher = Sha256::default();
                    Update::update(&mut hasher, &block);
                    Update::update(&mut hasher, &c);
                    Update::update(&mut hasher, &in_[..inblocks * n]);
                    let hash = hasher.finalize();
                    out.copy_from_slice(&hash[..n]);
                }
            }

            fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]) -> Result<(), Error> {
                let mut mac = Hmac::<Sha512>::new_from_slice(sk_prf).map_err(|_| Error::Internal)?;
                Update::update(&mut mac, optrand);
                Update::update(&mut mac, msg);
                let result = mac.finalize().into_bytes();
                r.copy_from_slice(&result[..Self::N]);
                Ok(())
            }

            fn hash_message(digest: &mut [u8], tree: &mut u64, leaf_idx: &mut u32, r: &[u8], pk: &[u8], msg: &[u8]) {
                let n = Self::N;
                let fors_msg_bytes = Self::MD;
                let tree_bits = Self::H - Self::H_PRIME;
                let tree_bytes = tree_bits.div_ceil(8);
                let leaf_bits = Self::H_PRIME;
                let leaf_bytes = leaf_bits.div_ceil(8);
                let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;

                let mut hasher = Sha512::default();
                Update::update(&mut hasher, r);
                Update::update(&mut hasher, pk);
                Update::update(&mut hasher, msg);
                let seed_core = hasher.finalize();

                let mgf_seed_len = 2 * n + 64;
                let mut mgf_seed = SecretVec::<u8>::new(mgf_seed_len);
                mgf_seed[..n].copy_from_slice(r);
                mgf_seed[n..2 * n].copy_from_slice(&pk[..n]);
                mgf_seed[2 * n..mgf_seed_len].copy_from_slice(&seed_core);

                let mut buf = alloc::vec![0u8; dgst_bytes];
                mgf1_512(&mut buf, &mgf_seed);

                digest[..fors_msg_bytes].copy_from_slice(&buf[..fors_msg_bytes]);

                let mut tree_val = 0u64;
                for &b in &buf[fors_msg_bytes..fors_msg_bytes + tree_bytes] {
                    tree_val = (tree_val << 8) | u64::from(b);
                }
                if tree_bits < 64 {
                    *tree = tree_val & ((1u64 << tree_bits) - 1);
                } else {
                    *tree = tree_val;
                }

                let mut leaf_val = 0u32;
                for &b in &buf[fors_msg_bytes + tree_bytes..fors_msg_bytes + tree_bytes + leaf_bytes] {
                    leaf_val = (leaf_val << 8) | u32::from(b);
                }
                if leaf_bits < 32 {
                    *leaf_idx = leaf_val & ((1u32 << leaf_bits) - 1);
                } else {
                    *leaf_idx = leaf_val;
                }
            }
        })+
    };
}

impl_hash_sha2_512!(
    Sha2_192s: 24, 63, 7, 9, 17, 14, 30, 51, 48, 96, 16224, 72, 1224, 6120, 30,
    Sha2_192f: 24, 66, 22, 3, 33, 8, 33, 51, 48, 96, 35664, 72, 1224, 7128, 33,
    Sha2_256s: 32, 64, 8, 8, 22, 14, 39, 67, 64, 128, 29792, 96, 2144, 10560, 39,
    Sha2_256f: 32, 68, 17, 4, 35, 9, 40, 67, 64, 128, 49856, 96, 2144, 11200, 40,
);

// -----------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------

/// Base-2^b encoding (Algorithm 3)
fn base_2b(out: &mut [u16], x: &[u8], b: usize) {
    let mut bits = 0usize;
    let mut i = 0;
    let mut total = 0usize;
    for out_val in out.iter_mut() {
        while bits < b {
            total = (total << 8) | x[i] as usize;
            bits += 8;
            i += 1;
        }
        bits -= b;
        *out_val = ((total >> bits) & ((1 << b) - 1)) as u16;
        total &= (1 << bits) - 1;
    }
}

// -----------------------------------------------------------------------
// WOTS+ algorithms
// -----------------------------------------------------------------------

const WOTS_W: u32 = 16;
const WOTS_LOGW: u32 = 4;

fn wots_chain<H: Hash>(
    x: &[u8],
    i: u32,
    s: u32,
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let n = H::N;
    let mut tmp = SecretVec::<u8>::new(x.len());
    tmp.copy_from_slice(x);
    let mut adrs = adrs.clone();
    for j in i..(i + s) {
        adrs.hash_adrs.set(j);
        let mut out = SecretVec::<u8>::new(n);
        H::thash(&mut out, &tmp, 1, pub_seed, adrs_bytes(&adrs)?);
        tmp = out;
    }
    Ok(tmp)
}

fn wots_pk_gen<H: Hash>(
    sk_seed: &[u8],
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let n = H::N;
    let wots_len = H::WOTS_LEN;
    let a = adrs.clone();
    let sa = a.prf_adrs();
    let mut tmp = SecretVec::<u8>::new(wots_len * n);
    for i in 0..wots_len {
        let i = i as u32;
        let mut sa2 = sa.clone();
        sa2.chain_adrs.set(i);
        let mut a2 = a.clone();
        a2.chain_adrs.set(i);
        let mut sk = SecretVec::<u8>::new(n);
        H::prf_addr(&mut sk, pub_seed, sk_seed, adrs_bytes(&sa2)?);
        let chain = wots_chain::<H>(&sk, 0, (1 << WOTS_LOGW) - 1, &a2, pub_seed)?;
        tmp[i as usize * n..(i as usize + 1) * n].copy_from_slice(chain.as_ref());
    }
    let mut out = SecretVec::<u8>::new(n);
    H::thash(
        &mut out,
        &tmp,
        wots_len,
        pub_seed,
        adrs_bytes(&a.pk_adrs())?,
    );
    Ok(out)
}

fn wots_sign<H: Hash>(
    m: &[u8],
    sk_seed: &[u8],
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = H::N;
    let wots_len = H::WOTS_LEN;
    let len1 = n * 8 / (WOTS_LOGW as usize);
    let len2 = 3;
    let mut msg_base_w = alloc::vec![0u16; len1 + len2];
    base_2b(&mut msg_base_w[..len1], m, WOTS_LOGW as usize);

    let mut csum = 0u32;
    for i in 0..len1 {
        csum += (WOTS_W - 1) - u32::from(msg_base_w[i]);
    }
    csum <<= (8 - ((len2 * (WOTS_LOGW as usize)) % 8)) % 8;
    let csum_bytes = csum.to_be_bytes();
    let csum_bytes_len = (len2 * (WOTS_LOGW as usize)).div_ceil(8);
    base_2b(
        &mut msg_base_w[len1..],
        &csum_bytes[4 - csum_bytes_len..],
        WOTS_LOGW as usize,
    );

    let mut sig = Vec::with_capacity(wots_len * n);
    let mut a = adrs.clone();
    let mut sa = a.prf_adrs();
    for i in 0..wots_len {
        let i = i as u32;
        sa.chain_adrs.set(i);
        a.chain_adrs.set(i);
        let mut sk = SecretVec::<u8>::new(n);
        H::prf_addr(&mut sk, pub_seed, sk_seed, adrs_bytes(&sa)?);
        let chain = wots_chain::<H>(&sk, 0, u32::from(msg_base_w[i as usize]), &a, pub_seed)?;
        sig.extend_from_slice(&chain);
    }
    Ok(sig)
}

fn wots_pk_from_sig<H: Hash>(
    sig: &[u8],
    m: &[u8],
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let n = H::N;
    let wots_len = H::WOTS_LEN;
    let len1 = n * 8 / (WOTS_LOGW as usize);
    let len2 = 3;
    let mut msg_base_w = alloc::vec![0u16; len1 + len2];
    base_2b(&mut msg_base_w[..len1], m, WOTS_LOGW as usize);

    let mut csum = 0u32;
    for i in 0..len1 {
        csum += (WOTS_W - 1) - u32::from(msg_base_w[i]);
    }
    csum <<= (8 - ((len2 * (WOTS_LOGW as usize)) % 8)) % 8;
    let csum_bytes = csum.to_be_bytes();
    let csum_bytes_len = (len2 * (WOTS_LOGW as usize)).div_ceil(8);
    base_2b(
        &mut msg_base_w[len1..],
        &csum_bytes[4 - csum_bytes_len..],
        WOTS_LOGW as usize,
    );

    let mut tmp = SecretVec::<u8>::new(wots_len * n);
    let mut a = adrs.clone();
    for i in 0..wots_len {
        a.chain_adrs.set(i as u32);
        let mi = u32::from(msg_base_w[i]);
        let chain = wots_chain::<H>(&sig[i * n..(i + 1) * n], mi, WOTS_W - 1 - mi, &a, pub_seed)?;
        tmp[i * n..(i + 1) * n].copy_from_slice(chain.as_ref());
    }
    let mut out = SecretVec::<u8>::new(n);
    H::thash(
        &mut out,
        &tmp,
        wots_len,
        pub_seed,
        adrs_bytes(&a.pk_adrs())?,
    );
    Ok(out)
}

// -----------------------------------------------------------------------
// XMSS algorithms
// -----------------------------------------------------------------------

fn xmss_node<H: Hash>(
    sk_seed: &[u8],
    node: u32,
    height: u32,
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    debug_assert!(height <= H::H_PRIME as u32);
    debug_assert!(node < (1u32 << (H::H_PRIME as u32 - height)));
    if height == 0 {
        let mut adrs = adrs.clone();
        adrs.key_pair_adrs.set(node);
        wots_pk_gen::<H>(sk_seed, &adrs, pub_seed)
    } else {
        let lnode = xmss_node::<H>(sk_seed, 2 * node, height - 1, adrs, pub_seed)?;
        let rnode = xmss_node::<H>(sk_seed, 2 * node + 1, height - 1, adrs, pub_seed)?;
        let mut a = adrs.tree_adrs();
        a.tree_height.set(height);
        a.tree_index.set(node);
        let mut out = SecretVec::<u8>::new(H::N);
        let mut inp = SecretVec::<u8>::new(2 * H::N);
        inp[..H::N].copy_from_slice(lnode.as_ref());
        inp[H::N..2 * H::N].copy_from_slice(rnode.as_ref());
        H::thash(&mut out, &inp, 2, pub_seed, adrs_bytes(&a)?);
        Ok(out)
    }
}

fn xmss_pk_from_sig<H: Hash>(
    idx: u32,
    sig: &[u8],
    msg: &[u8],
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let n = H::N;
    let hprime = H::H_PRIME;
    let wots_sig_size = H::WOTS_LEN * n;
    let sig_wots = &sig[..wots_sig_size];
    let mut a = adrs.clone();
    a.key_pair_adrs.set(idx);
    let mut node = wots_pk_from_sig::<H>(sig_wots, msg, &a, pub_seed)?;
    let mut idx = idx;
    for j in 0..hprime {
        let sibling = &sig[wots_sig_size + j * n..wots_sig_size + (j + 1) * n];
        let mut ta = adrs.tree_adrs();
        ta.tree_height.set((j + 1) as u32);
        let rem = idx & 1;
        idx >>= 1;
        ta.tree_index.set(idx);
        let mut out = SecretVec::<u8>::new(n);
        let mut inp = SecretVec::<u8>::new(2 * n);
        if rem == 0 {
            inp[..n].copy_from_slice(node.as_ref());
            inp[n..2 * n].copy_from_slice(sibling);
        } else {
            inp[..n].copy_from_slice(sibling);
            inp[n..2 * n].copy_from_slice(node.as_ref());
        }
        H::thash(&mut out, &inp, 2, pub_seed, adrs_bytes(&ta)?);
        node = out;
    }
    Ok(node)
}

// -----------------------------------------------------------------------
// Hypertree algorithms
// -----------------------------------------------------------------------

fn ht_sign<H: Hash>(
    message: &[u8],
    sk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pub_seed: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = H::N;
    let d = H::D;
    let hprime = H::H_PRIME;
    let wots_sig_size = H::WOTS_LEN * n;
    let xmss_sig_size = wots_sig_size + hprime * n;
    let mut sig = alloc::vec![0u8; d * xmss_sig_size];
    let mut root = SecretVec::<u8>::new(message.len());
    root.copy_from_slice(message);
    let mut tree = idx_tree;
    let mut idx_leaf = idx_leaf;

    for j in 0..d {
        let mut adrs = WotsHash::default();
        adrs.layer_adrs.set(j as u32);
        adrs.tree_adrs_low.set(tree);
        let xmss_sig = xmss_sign::<H>(&root, sk_seed, idx_leaf, &adrs, pub_seed)?;
        sig[j * xmss_sig_size..(j + 1) * xmss_sig_size].copy_from_slice(&xmss_sig);
        if j != d - 1 {
            root = xmss_pk_from_sig::<H>(idx_leaf, &xmss_sig, &root, &adrs, pub_seed)?;
        }
        idx_leaf = (tree & ((1u64 << hprime) - 1)) as u32;
        tree >>= hprime;
    }
    Ok(sig)
}

fn ht_verify<H: Hash>(
    message: &[u8],
    sig: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
    pub_seed: &[u8],
) -> Result<bool, Error> {
    let n = H::N;
    let d = H::D;
    let hprime = H::H_PRIME;
    let wots_sig_size = H::WOTS_LEN * n;
    let xmss_sig_size = wots_sig_size + hprime * n;
    let mut root = SecretVec::<u8>::new(message.len());
    root.copy_from_slice(message);
    let mut tree = idx_tree;
    let mut idx_leaf = idx_leaf;

    for j in 0..d {
        let mut adrs = WotsHash::default();
        adrs.layer_adrs.set(j as u32);
        adrs.tree_adrs_low.set(tree);
        let xmss_sig = &sig[j * xmss_sig_size..(j + 1) * xmss_sig_size];
        root = xmss_pk_from_sig::<H>(idx_leaf, xmss_sig, &root, &adrs, pub_seed)?;
        idx_leaf = (tree & ((1u64 << hprime) - 1)) as u32;
        tree >>= hprime;
    }
    Ok(root.as_ref() == pk_root)
}

fn xmss_sign<H: Hash>(
    message: &[u8],
    sk_seed: &[u8],
    idx: u32,
    adrs: &WotsHash,
    pub_seed: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = H::N;
    let hprime = H::H_PRIME;
    let wots_sig_size = H::WOTS_LEN * n;
    let mut a = adrs.clone();
    a.key_pair_adrs.set(idx);
    let mut idx = idx;
    let mut auth = Vec::with_capacity(hprime * n);
    for j in 0..hprime {
        let node = xmss_node::<H>(sk_seed, idx ^ 1, j as u32, &a, pub_seed)?;
        auth.extend_from_slice(&node);
        idx >>= 1;
    }
    let wots_sig = wots_sign::<H>(message, sk_seed, &a, pub_seed)?;
    let mut sig = Vec::with_capacity(wots_sig_size + hprime * n);
    sig.extend_from_slice(&wots_sig);
    sig.extend_from_slice(&auth);
    Ok(sig)
}

// -----------------------------------------------------------------------
// FORS algorithms
// -----------------------------------------------------------------------

fn fors_sk_gen<H: Hash>(
    sk_seed: &[u8],
    adrs: &ForsTree,
    idx: u32,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let mut a = adrs.prf_adrs();
    a.tree_index.set(idx);
    let mut out = SecretVec::<u8>::new(H::N);
    H::prf_addr(&mut out, pub_seed, sk_seed, adrs_bytes(&a)?);
    Ok(out)
}

fn fors_node<H: Hash>(
    sk_seed: &[u8],
    i: u32,
    z: u32,
    adrs: &ForsTree,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let mut a = adrs.clone();
    a.tree_height.set(z);
    a.tree_index.set(i);
    if z == 0 {
        let mut sa = a.clone();
        sa.type_const.set(6);
        let mut sk = SecretVec::<u8>::new(H::N);
        H::prf_addr(&mut sk, pub_seed, sk_seed, adrs_bytes(&sa)?);
        let mut out = SecretVec::<u8>::new(H::N);
        H::thash(&mut out, &sk, 1, pub_seed, adrs_bytes(&a)?);
        Ok(out)
    } else {
        let lnode = fors_node::<H>(sk_seed, 2 * i, z - 1, adrs, pub_seed)?;
        let rnode = fors_node::<H>(sk_seed, 2 * i + 1, z - 1, adrs, pub_seed)?;
        let mut out = SecretVec::<u8>::new(H::N);
        let mut inp = SecretVec::<u8>::new(2 * H::N);
        inp[..H::N].copy_from_slice(lnode.as_ref());
        inp[H::N..2 * H::N].copy_from_slice(rnode.as_ref());
        H::thash(&mut out, &inp, 2, pub_seed, adrs_bytes(&a)?);
        Ok(out)
    }
}

fn fors_sign<H: Hash>(
    md: &[u8],
    sk_seed: &[u8],
    adrs: &ForsTree,
    pub_seed: &[u8],
) -> Result<Vec<u8>, Error> {
    let n = H::N;
    let k = H::K;
    let a = H::A;
    let mt_size = n + a * n;

    let mut indices = alloc::vec![0u16; k];
    base_2b(&mut indices, md, a);

    let mut sig = Vec::with_capacity(k * mt_size);
    for i in 0..k {
        let idx_base = (i << a) as u32;
        let sk = fors_sk_gen::<H>(sk_seed, adrs, idx_base + u32::from(indices[i]), pub_seed)?;
        sig.extend_from_slice(&sk);
        for j in 0..a {
            let s = (indices[i] >> j) ^ 1;
            let auth = fors_node::<H>(
                sk_seed,
                (i << (a - j)) as u32 + u32::from(s),
                j as u32,
                adrs,
                pub_seed,
            )?;
            sig.extend_from_slice(&auth);
        }
    }
    Ok(sig)
}

fn fors_pk_from_sig<H: Hash>(
    sig: &[u8],
    md: &[u8],
    adrs: &ForsTree,
    pub_seed: &[u8],
) -> Result<SecretVec<u8>, Error> {
    let n = H::N;
    let k = H::K;
    let a = H::A;
    let mt_size = n + a * n;

    let mut indices = alloc::vec![0u16; k];
    base_2b(&mut indices, md, a);

    let mut roots = SecretVec::<u8>::new(k * n);
    for i in 0..k {
        let idx_base = (i << a) as u32;
        let sk = &sig[i * mt_size..i * mt_size + n];
        let mut adrs = adrs.clone();
        adrs.tree_height.set(0);
        adrs.tree_index.set(idx_base + u32::from(indices[i]));
        let mut node = {
            let mut out = SecretVec::<u8>::new(n);
            H::thash(&mut out, sk, 1, pub_seed, adrs_bytes(&adrs)?);
            out
        };
        for j in 0..a {
            adrs.tree_height.set((j + 1) as u32);
            adrs.tree_index.set(adrs.tree_index.get() >> 1);
            let sibling = &sig[i * mt_size + n + j * n..i * mt_size + n + (j + 1) * n];
            let mut out = SecretVec::<u8>::new(n);
            let mut inp = SecretVec::<u8>::new(2 * n);
            if (indices[i] >> j) & 1 == 0 {
                inp[..n].copy_from_slice(node.as_ref());
                inp[n..2 * n].copy_from_slice(sibling);
            } else {
                inp[..n].copy_from_slice(sibling);
                inp[n..2 * n].copy_from_slice(node.as_ref());
            }
            H::thash(&mut out, &inp, 2, pub_seed, adrs_bytes(&adrs)?);
            node = out;
        }
        roots[i * n..(i + 1) * n].copy_from_slice(node.as_ref());
    }
    let mut out = SecretVec::<u8>::new(n);
    H::thash(
        &mut out,
        &roots,
        k,
        pub_seed,
        adrs_bytes(&adrs.fors_roots())?,
    );
    Ok(out)
}

// -----------------------------------------------------------------------
// Public API free functions
// -----------------------------------------------------------------------

/// Generate a keypair from seeds. Returns (vk_bytes, sk_bytes).
pub(crate) fn slh_keygen<H: Hash>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let n = H::N;
    let mut adrs = WotsHash::default();
    adrs.layer_adrs.set((H::D - 1) as u32);
    let pk_root = xmss_node::<H>(sk_seed, 0, H::H_PRIME as u32, &adrs, pk_seed)?;

    let mut vk_bytes = Vec::with_capacity(2 * n);
    vk_bytes.extend_from_slice(pk_seed);
    vk_bytes.extend_from_slice(&pk_root);

    let mut sk_bytes = zeroize::Zeroizing::new(Vec::with_capacity(4 * n));
    sk_bytes.extend_from_slice(sk_seed);
    sk_bytes.extend_from_slice(sk_prf);
    sk_bytes.extend_from_slice(&vk_bytes);

    Ok((vk_bytes, core::mem::take(sk_bytes.as_mut())))
}

/// Sign a message. Returns serialized signature bytes.
pub(crate) fn slh_sign_internal<H: Hash>(
    sk: &[u8],
    msg: &[u8],
    opt_rand: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let n = H::N;
    let pk_seed = &sk[2 * n..3 * n];
    let r = match opt_rand {
        Some(r) => r,
        None => pk_seed,
    };

    let fors_msg_bytes = H::MD;
    let tree_bits = H::H - H::H_PRIME;
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bits = H::H_PRIME;
    let leaf_bytes = leaf_bits.div_ceil(8);
    let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;
    let mut digest = alloc::vec![0u8; dgst_bytes];
    let mut tree = 0u64;
    let mut leaf_idx = 0u32;

    let mut r_seed = SecretVec::<u8>::new(n);
    <H as Hash>::gen_message_random(&mut r_seed, &sk[n..2 * n], r, msg)?;

    let pk_full = &sk[2 * n..4 * n];
    <H as Hash>::hash_message(&mut digest, &mut tree, &mut leaf_idx, &r_seed, pk_full, msg);

    let md = &digest[..fors_msg_bytes];
    let adrs = ForsTree::new(tree, leaf_idx);

    let pub_seed = pk_seed;
    let fors_sig = fors_sign::<H>(md, &sk[..n], &adrs, pub_seed)?;
    let fors_pk = fors_pk_from_sig::<H>(&fors_sig, md, &adrs, pub_seed)?;
    let ht_sig = ht_sign::<H>(&fors_pk, &sk[..n], tree, leaf_idx, pub_seed)?;

    let mut sig = Vec::with_capacity(H::SIG_BYTES);
    sig.extend_from_slice(&r_seed);
    sig.extend_from_slice(&fors_sig);
    sig.extend_from_slice(&ht_sig);
    Ok(sig)
}

/// Verify a signature. Returns true if valid.
pub(crate) fn slh_verify_internal<H: Hash>(
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    let n = H::N;
    let fors_msg_bytes = H::MD;
    let tree_bits = H::H - H::H_PRIME;
    let tree_bytes = tree_bits.div_ceil(8);
    let leaf_bits = H::H_PRIME;
    let leaf_bytes = leaf_bits.div_ceil(8);
    let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;
    let fors_size = H::FORS_BYTES;
    let wots_sig_size = H::WOTS_LEN * n;
    let _xmss_sig_size = wots_sig_size + H::H_PRIME * n;

    let r_seed = &sig[..n];
    let fors_sig = &sig[n..n + fors_size];
    let ht_sig = &sig[n + fors_size..];

    let mut digest = alloc::vec![0u8; dgst_bytes];
    let mut tree = 0u64;
    let mut leaf_idx = 0u32;
    <H as Hash>::hash_message(&mut digest, &mut tree, &mut leaf_idx, r_seed, pk, msg);

    let md = &digest[..fors_msg_bytes];
    let adrs = ForsTree::new(tree, leaf_idx);

    let pub_seed = &pk[..n];
    let fors_pk = fors_pk_from_sig::<H>(fors_sig, md, &adrs, pub_seed)?;
    ht_verify::<H>(&fors_pk, ht_sig, tree, leaf_idx, &pk[n..], pub_seed)
}

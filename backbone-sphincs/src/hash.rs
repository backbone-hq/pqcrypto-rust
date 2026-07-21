use crate::params::{
    Params, Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use backbone_pqcrypto_internals::secret::SecretArray;
use sha2::{Sha256, Sha512};
use sha3::{
    digest::ExtendableOutput, digest::FixedOutput, digest::Update, digest::XofReader, Shake256,
};

/// Hash function interface for SPHINCS+.
///
/// Provides the address-offset constants and cryptographic primitives
/// used by the SPHINCS+ signing scheme. Each parameter set (SHA-2 or SHAKE)
/// implements this trait with concrete hash logic and address layout.
pub trait Hash: Params {
    /// Byte offset of the layer field in the 32-byte address.
    const OFFSET_LAYER: usize;
    /// Byte offset of the tree field in the 32-byte address.
    const OFFSET_TREE: usize;
    /// Byte offset of the type field in the 32-byte address.
    const OFFSET_TYPE: usize;
    /// Byte offset of the key-pair address (high byte) in the 32-byte address.
    const OFFSET_KP_ADDR2: usize;
    /// Byte offset of the key-pair address (low byte) in the 32-byte address.
    const OFFSET_KP_ADDR1: usize;
    /// Byte offset of the chain address in the 32-byte address.
    const OFFSET_CHAIN_ADDR: usize;
    /// Byte offset of the hash address in the 32-byte address.
    const OFFSET_HASH_ADDR: usize;
    /// Byte offset of the tree height field in the 32-byte address.
    const OFFSET_TREE_HGT: usize;
    /// Byte offset of the tree index field in the 32-byte address.
    const OFFSET_TREE_INDEX: usize;

    /// Pseudorandom function for address-level key derivation.
    fn prf_addr(out: &mut [u8], pub_seed: &[u8], sk_seed: &[u8], addr: &[u8; 32]);
    /// Hash-function-based tweakable hashing ("T-hash") for SPHINCS+.
    fn thash(out: &mut [u8], in_: &[u8], inblocks: usize, pub_seed: &[u8], addr: &[u8; 32]);
    /// Generate the message-randomness value `r` used during signing.
    fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]);
    /// Hash a message into its FORS digest, tree index, and leaf index components.
    fn hash_message(
        digest: &mut [u8],
        tree: &mut u64,
        leaf_idx: &mut u32,
        r: &[u8],
        pk: &[u8],
        msg: &[u8],
    );
}

macro_rules! impl_shake_hash {
    ($($variant:ident),+ $(,)?) => {
        $(impl Hash for $variant {
            const OFFSET_LAYER: usize = 3;
            const OFFSET_TREE: usize = 8;
            const OFFSET_TYPE: usize = 19;
            const OFFSET_KP_ADDR2: usize = 22;
            const OFFSET_KP_ADDR1: usize = 23;
            const OFFSET_CHAIN_ADDR: usize = 27;
            const OFFSET_HASH_ADDR: usize = 31;
            const OFFSET_TREE_HGT: usize = 27;
            const OFFSET_TREE_INDEX: usize = 28;

            fn prf_addr(
                out: &mut [u8],
                pub_seed: &[u8],
                sk_seed: &[u8],
                addr: &[u8; 32],
            ) {
                let mut shake = Shake256::default();
                shake.update(pub_seed);
                shake.update(addr);
                shake.update(sk_seed);
                let mut xof = shake.finalize_xof();
                xof.read(out);
            }

            fn thash(
                out: &mut [u8],
                in_: &[u8],
                _inblocks: usize,
                pub_seed: &[u8],
                addr: &[u8; 32],
            ) {
                let mut shake = Shake256::default();
                shake.update(pub_seed);
                shake.update(addr);
                shake.update(in_);
                let mut xof = shake.finalize_xof();
                xof.read(out);
            }

            fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]) {
                let mut shake = Shake256::default();
                shake.update(sk_prf);
                shake.update(optrand);
                shake.update(msg);
                let mut xof = shake.finalize_xof();
                xof.read(r);
            }

            fn hash_message(
                digest: &mut [u8],
                tree: &mut u64,
                leaf_idx: &mut u32,
                r: &[u8],
                pk: &[u8],
                msg: &[u8],
            ) {
                let fors_msg_bytes = (Self::LOG_T * Self::K).div_ceil(8);
                let tree_bits = Self::TREE_H * (Self::D - 1);
                let tree_bytes = (tree_bits).div_ceil(8);
                let leaf_bits = Self::TREE_H;
                let leaf_bytes = (leaf_bits).div_ceil(8);
                let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;

                let mut buf = [0u8; 128];
                let buf = &mut buf[..dgst_bytes];
                let mut shake = Shake256::default();
                shake.update(r);
                shake.update(pk);
                shake.update(msg);
                let mut xof = shake.finalize_xof();
                xof.read(buf);

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

impl_shake_hash!(Shake128s, Shake128f, Shake192s, Shake192f, Shake256s, Shake256f,);

// ─── SHA-2 helpers (MGF1) ───

fn mgf1_256(out: &mut [u8], seed: &[u8]) {
    let mut counter = 0u32;
    let mut offset = 0;
    while offset < out.len() {
        let mut hasher = Sha256::default();
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        let hash = hasher.finalize_fixed();
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
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        let hash = hasher.finalize_fixed();
        let end = (offset + 64).min(out.len());
        out[offset..end].copy_from_slice(&hash[..end - offset]);
        offset += 64;
        counter += 1;
    }
}

// ─── SHA-2 (SHA-256) — 128s, 128f ───

macro_rules! impl_sha2_256_hash {
    ($($variant:ident),+ $(,)?) => {
        $(impl Hash for $variant {
            const OFFSET_LAYER: usize = 0;
            const OFFSET_TREE: usize = 1;
            const OFFSET_TYPE: usize = 9;
            const OFFSET_KP_ADDR2: usize = 12;
            const OFFSET_KP_ADDR1: usize = 13;
            const OFFSET_CHAIN_ADDR: usize = 17;
            const OFFSET_HASH_ADDR: usize = 21;
            const OFFSET_TREE_HGT: usize = 17;
            const OFFSET_TREE_INDEX: usize = 18;

            fn prf_addr(
                out: &mut [u8],
                pub_seed: &[u8],
                sk_seed: &[u8],
                addr: &[u8; 32],
            ) {
                let n = out.len();
                let mut block = [0u8; 64];
                block[..n].copy_from_slice(pub_seed);
                let mut hasher = Sha256::default();
                hasher.update(&block);
                hasher.update(&addr[..22]);
                hasher.update(sk_seed);
                let hash = hasher.finalize_fixed();
                out.copy_from_slice(&hash[..n]);
            }

            fn thash(
                out: &mut [u8],
                in_: &[u8],
                inblocks: usize,
                pub_seed: &[u8],
                addr: &[u8; 32],
            ) {
                let n = out.len();
                let mut block = [0u8; 64];
                block[..n].copy_from_slice(pub_seed);
                let mut hasher = Sha256::default();
                hasher.update(&block);
                hasher.update(&addr[..22]);
                hasher.update(&in_[..inblocks * n]);
                let hash = hasher.finalize_fixed();
                out.copy_from_slice(&hash[..n]);
            }

            fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]) {
                let n = sk_prf.len();
                let mut ipad = SecretArray::<u8, 64>::new();
                ipad.fill(0x36);
                for i in 0..n { ipad[i] ^= sk_prf[i]; }
                let mut inner = Sha256::default();
                inner.update(ipad.as_ref());
                inner.update(optrand);
                inner.update(msg);
                let h1 = inner.finalize_fixed();
                let mut opad = SecretArray::<u8, 64>::new();
                opad.fill(0x5c);
                for i in 0..n { opad[i] ^= sk_prf[i]; }
                let mut outer = Sha256::default();
                outer.update(opad.as_ref());
                outer.update(&h1);
                let h2 = outer.finalize_fixed();
                r.copy_from_slice(&h2[..n]);
            }

            fn hash_message(
                digest: &mut [u8],
                tree: &mut u64,
                leaf_idx: &mut u32,
                r: &[u8],
                pk: &[u8],
                msg: &[u8],
            ) {
                let n = Self::N;
                let fors_msg_bytes = (Self::LOG_T * Self::K).div_ceil(8);
                let tree_bits = Self::TREE_H * (Self::D - 1);
                let tree_bytes = (tree_bits).div_ceil(8);
                let leaf_bits = Self::TREE_H;
                let leaf_bytes = (leaf_bits).div_ceil(8);
                let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;

                let mut hasher = Sha256::default();
                hasher.update(r);
                hasher.update(pk);
                hasher.update(msg);
                let seed_core = hasher.finalize_fixed();

                let mut mgf_seed = [0u8; 128];
                let mgf_seed_len = 2 * n + 32;
                let mgf_seed = &mut mgf_seed[..mgf_seed_len];
                mgf_seed[..n].copy_from_slice(r);
                mgf_seed[n..2 * n].copy_from_slice(&pk[..n]);
                mgf_seed[2 * n..].copy_from_slice(&seed_core);

                let mut buf = [0u8; 128];
                let buf = &mut buf[..dgst_bytes];
                mgf1_256(buf, mgf_seed);

                digest[..fors_msg_bytes].copy_from_slice(&buf[..fors_msg_bytes]);

                let mut tree_val = 0u64;
                for &b in &buf[fors_msg_bytes..fors_msg_bytes + tree_bytes] {
                    tree_val = (tree_val << 8) | u64::from(b);
                }
                *tree = if tree_bits < 64 {
                    tree_val & ((1u64 << tree_bits) - 1)
                } else {
                    tree_val
                };

                let mut leaf_val = 0u32;
                for &b in &buf[fors_msg_bytes + tree_bytes..fors_msg_bytes + tree_bytes + leaf_bytes] {
                    leaf_val = (leaf_val << 8) | u32::from(b);
                }
                *leaf_idx = if leaf_bits < 32 {
                    leaf_val & ((1u32 << leaf_bits) - 1)
                } else {
                    leaf_val
                };
            }
        })+
    };
}

// ─── SHA-2 (SHA-512) — 192s, 192f, 256s, 256f ───

macro_rules! impl_sha2_512_hash {
    ($($variant:ident),+ $(,)?) => {
        $(impl Hash for $variant {
            const OFFSET_LAYER: usize = 0;
            const OFFSET_TREE: usize = 1;
            const OFFSET_TYPE: usize = 9;
            const OFFSET_KP_ADDR2: usize = 12;
            const OFFSET_KP_ADDR1: usize = 13;
            const OFFSET_CHAIN_ADDR: usize = 17;
            const OFFSET_HASH_ADDR: usize = 21;
            const OFFSET_TREE_HGT: usize = 17;
            const OFFSET_TREE_INDEX: usize = 18;

            fn prf_addr(
                out: &mut [u8],
                pub_seed: &[u8],
                sk_seed: &[u8],
                addr: &[u8; 32],
            ) {
                let n = out.len();
                let mut block = [0u8; 64];
                block[..n].copy_from_slice(pub_seed);
                let mut hasher = Sha256::default();
                hasher.update(&block);
                hasher.update(&addr[..22]);
                hasher.update(sk_seed);
                let hash = hasher.finalize_fixed();
                out.copy_from_slice(&hash[..n]);
            }

            fn thash(
                out: &mut [u8],
                in_: &[u8],
                inblocks: usize,
                pub_seed: &[u8],
                addr: &[u8; 32],
            ) {
                let n = out.len();
                if inblocks > 1 {
                    let mut block = [0u8; 128];
                    block[..n].copy_from_slice(pub_seed);
                    let mut hasher = Sha512::default();
                    hasher.update(&block);
                    hasher.update(&addr[..22]);
                    hasher.update(&in_[..inblocks * n]);
                    let hash = hasher.finalize_fixed();
                    out.copy_from_slice(&hash[..n]);
                } else {
                    let mut block = [0u8; 64];
                    block[..n].copy_from_slice(pub_seed);
                    let mut hasher = Sha256::default();
                    hasher.update(&block);
                    hasher.update(&addr[..22]);
                    hasher.update(&in_[..inblocks * n]);
                    let hash = hasher.finalize_fixed();
                    out.copy_from_slice(&hash[..n]);
                }
            }

            fn gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], msg: &[u8]) {
                let n = sk_prf.len();
                let mut ipad = SecretArray::<u8, 128>::new();
                ipad.fill(0x36);
                for i in 0..n { ipad[i] ^= sk_prf[i]; }
                let mut inner = Sha512::default();
                inner.update(ipad.as_ref());
                inner.update(optrand);
                inner.update(msg);
                let h1 = inner.finalize_fixed();
                let mut opad = SecretArray::<u8, 128>::new();
                opad.fill(0x5c);
                for i in 0..n { opad[i] ^= sk_prf[i]; }
                let mut outer = Sha512::default();
                outer.update(opad.as_ref());
                outer.update(&h1);
                let h2 = outer.finalize_fixed();
                r.copy_from_slice(&h2[..n]);
            }

            fn hash_message(
                digest: &mut [u8],
                tree: &mut u64,
                leaf_idx: &mut u32,
                r: &[u8],
                pk: &[u8],
                msg: &[u8],
            ) {
                let n = Self::N;
                let fors_msg_bytes = (Self::LOG_T * Self::K).div_ceil(8);
                let tree_bits = Self::TREE_H * (Self::D - 1);
                let tree_bytes = (tree_bits).div_ceil(8);
                let leaf_bits = Self::TREE_H;
                let leaf_bytes = (leaf_bits).div_ceil(8);
                let dgst_bytes = fors_msg_bytes + tree_bytes + leaf_bytes;

                let mut hasher = Sha512::default();
                hasher.update(r);
                hasher.update(pk);
                hasher.update(msg);
                let seed_core = hasher.finalize_fixed();

                let mut mgf_seed = [0u8; 128];
                let mgf_seed_len = 2 * n + 64;
                let mgf_seed = &mut mgf_seed[..mgf_seed_len];
                mgf_seed[..n].copy_from_slice(r);
                mgf_seed[n..2 * n].copy_from_slice(&pk[..n]);
                mgf_seed[2 * n..].copy_from_slice(&seed_core);

                let mut buf = [0u8; 128];
                let buf = &mut buf[..dgst_bytes];
                mgf1_512(buf, mgf_seed);

                digest[..fors_msg_bytes].copy_from_slice(&buf[..fors_msg_bytes]);

                let mut tree_val = 0u64;
                for &b in &buf[fors_msg_bytes..fors_msg_bytes + tree_bytes] {
                    tree_val = (tree_val << 8) | u64::from(b);
                }
                *tree = if tree_bits < 64 {
                    tree_val & ((1u64 << tree_bits) - 1)
                } else {
                    tree_val
                };

                let mut leaf_val = 0u32;
                for &b in &buf[fors_msg_bytes + tree_bytes..fors_msg_bytes + tree_bytes + leaf_bytes] {
                    leaf_val = (leaf_val << 8) | u32::from(b);
                }
                *leaf_idx = if leaf_bits < 32 {
                    leaf_val & ((1u32 << leaf_bits) - 1)
                } else {
                    leaf_val
                };
            }
        })+
    };
}

impl_sha2_256_hash!(Sha2_128s, Sha2_128f);
impl_sha2_512_hash!(Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f);

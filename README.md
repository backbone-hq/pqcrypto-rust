# ![PQCrypto](./media/pqcrypto.png)

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Rust Edition](https://img.shields.io/badge/rust-2021-blue)
![Made by Backbone](https://img.shields.io/badge/made_by-Backbone-blue)

Pure Rust implementations of NIST-standardized post-quantum cryptographic algorithms — ready for production.

Every operation is verified byte-for-byte against official NIST Known Answer Test vectors and/or submission reference implementations. The test suite runs as part of `cargo test`.

- **Zero unsafe code** — the workspace enforces `unsafe_code = "forbid"` across every crate
- **Consistent native API** — every scheme uses the same per-variant module pattern
- **Built for reproducibility** — every scheme exposes a `keygen(seed)` entry point for deterministic key generation

### 🏗️ Background

PQCrypto provides pure Rust implementations of the following post-quantum cryptographic algorithms. All FIPS-standardized schemes (ML-KEM, ML-DSA, SPHINCS+, HQC) are validated against NIST ACVP vectors. The remaining schemes use submission-level reference vectors and transcript-hash tests for internal consistency.

| Crate | Algorithm | Standard | Type |
| ------- | ----------- | ---------- | ------ |
| `pqcrypto-ml-kem` | ML-KEM | FIPS 203 | KEM |
| `pqcrypto-ml-dsa` | ML-DSA | FIPS 204 | Signature |
| `pqcrypto-sphincs` | SPHINCS+ | FIPS 205 | Signature |
| `pqcrypto-hqc` | HQC | FIPS 207 | KEM |
| `pqcrypto-sntrup` | Streamlined NTRU Prime | — | KEM |
| `pqcrypto-ntruplr` | NTRU LPRime | — | KEM |
| `pqcrypto-mceliece` | Classic McEliece | — | KEM |

### 📇 Usage

Signatures and KEMs share the same per-variant module pattern:

```rust
// ── Sign ───────────────────────────────────────────────

use pqcrypto_ml_dsa::mldsa65;

let (pk, sk) = mldsa65::keygen(&[0u8; 32]).unwrap();
let sig = mldsa65::sign(&sk, b"msg").unwrap();
assert!(mldsa65::verify(&pk, b"msg", &sig));

// SPHINCS+ seeds are 48 bytes (128s) or 96 bytes (256s)
use pqcrypto_sphincs::shake128f;
let (pk, sk) = shake128f::keygen(&[0u8; 48]).unwrap();
let sig = shake128f::sign(&sk, b"msg").unwrap();
assert!(shake128f::verify(&pk, b"msg", &sig));

// ── Key Exchange ───────────────────────────────────────

use pqcrypto_ml_kem::mlkem768;

let (pk, sk) = mlkem768::keygen(&[0u8; 32]).unwrap();
let enc = mlkem768::encaps(&pk).unwrap();
let ss = mlkem768::decaps(&sk, &enc.ciphertext).unwrap();
assert_eq!(ss, enc.shared_secret);
```

All KEMs (`sntrup761`, `ntruplr761`, `hqc192`, `mceliece460896`) follow the same `keygen` → `encaps` → `decaps` pattern. All signatures (`mldsa44`, `mldsa65`, `mldsa87`, and every SPHINCS+ variant) follow `keygen` → `sign` → `verify`.

### 🔬 Design

#### Zero Unsafe

The workspace sets `unsafe_code = "forbid"` at the lint level. Every crate adheres to it — no raw pointers, no inline assembly, no platform-specific intrinsics in the main logic. The only SIMD is via the `safe_arch` crate's safe wrappers, gated behind the `simd` Cargo feature.

#### Deterministic API

Every scheme exposes a `keygen(seed)` entry point for deterministic key generation. This is essential for reproducibility in test vectors, protocol development, and scenarios where you control the randomness source. Signatures additionally expose `sign_deterministic` for fully deterministic signing.

#### Verification

Every crate validates against the highest available standard:

- **FIPS schemes** (ML-KEM, ML-DSA, SPHINCS+, HQC): byte-for-byte against official NIST ACVP `.rsp` vectors for keygen, encaps/sign, and decaps/verify.
- **Submission schemes** (McEliece, SNTRUP, NTRU LPRime): byte-for-byte against official reference vectors for decaps, plus transcript-hash tests proving internal consistency across 100 deterministic iterations.

The full KAT suite runs as part of the standard test harness:

```bash
cargo test --release
```

### 🧩 Building & SIMD

```bash
# Release build (all crates)
cargo build --release

# With SIMD acceleration (AVX2, PCLMULQDQ)
RUSTFLAGS="-C target-cpu=native" cargo build --release --features \
  pqcrypto-mceliece/simd,pqcrypto-hqc/simd,pqcrypto-ml-kem/simd,pqcrypto-ml-dsa/simd
```

When the `simd` feature is not enabled (or when building without `target-cpu=native`), the scalar fallback is used automatically — zero dependency cost.

### 📢 Caveats

These implementations have not undergone a formal security audit. As with all cryptographic software, we recommend third-party review before production use. See [SECURITY.md](SECURITY.md) for details.

---

Built by [Backbone](https://backbone.dev)

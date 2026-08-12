# ![PQCrypto](./media/pqcrypto.png)

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Rust Edition](https://img.shields.io/badge/rust-2021-blue)
![Made by Backbone](https://img.shields.io/badge/made_by-Backbone-blue)

Pure Rust implementations of post-quantum cryptographic algorithms.

Every operation is verified against official NIST Known Answer Test vectors and/or submission reference implementations. The test suite runs as part of `cargo test`.

- **Zero unsafe code** — the workspace enforces `unsafe_code = "forbid"` across every crate
- **Consistent API** — every scheme uses the same per-variant module patterns

### Background

PQCrypto provides pure Rust implementations of the following post-quantum cryptographic algorithms. ML-KEM, ML-DSA, and SPHINCS+ are validated against NIST ACVP vectors; HQC is validated byte-for-byte against the FIPS 207 reference implementation. The remaining schemes use submission-level reference vectors plus chained 100-round deterministic roundtrips for internal consistency.

| Crate | Algorithm | Standard | Type |
| ------- | ----------- | ---------- | ------ |
| `backbone-ml-kem` | ML-KEM | FIPS 203 | KEM |
| `backbone-ml-dsa` | ML-DSA | FIPS 204 | Signature |
| `backbone-sphincs` | SPHINCS+ | FIPS 205 | Signature |
| `backbone-hqc` | HQC | FIPS 207 | KEM |
| `backbone-sntrup` | Streamlined NTRU Prime | — | KEM |
| `backbone-ntruplr` | NTRU LPRime | — | KEM |
| `backbone-mceliece` | Classic McEliece | — | KEM |

### Usage

Signatures and KEMs share the same per-variant module pattern:

```rust
// ── Sign ───────────────────────────────────────────────

use backbone_ml_dsa::mldsa65;

let (pk, sk) = mldsa65::keygen().unwrap();
let sig = mldsa65::sign(&sk, b"msg", None, None).unwrap();
assert!(mldsa65::verify(&pk, b"msg", &sig, None, None).is_ok());

// Deterministic runs: seed a ChaCha20Rng with 32 bytes and pass it to *_with_rng
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
let (pk, sk) = mldsa65::keygen_with_rng(&mut rng).unwrap();

// SPHINCS+
use backbone_sphincs::shake128f;
let (pk, sk) = shake128f::keygen().unwrap();
let sig = shake128f::sign(&sk, b"msg", None, None).unwrap();
assert!(shake128f::verify(&pk, b"msg", &sig, None, None).is_ok());

// ── Key Exchange ───────────────────────────────────────

use backbone_ml_kem::mlkem768;

let (pk, sk) = mlkem768::keygen().unwrap();
let enc = mlkem768::encaps(&pk).unwrap();
let ss = mlkem768::decaps(&sk, &enc.ciphertext).unwrap();
assert_eq!(ss, enc.shared_secret);
```

All KEMs (`sntrup761`, `ntruplr761`, `hqc192`, `mceliece460896`) follow the same `keygen` → `encaps` → `decaps` pattern. All signatures (`mldsa44`, `mldsa65`, `mldsa87`, and every SPHINCS+ variant) follow `keygen` → `sign` → `verify`.

#### Verification

Every crate validates against the highest available standard:

- **FIPS schemes** (ML-KEM, ML-DSA, SPHINCS+, HQC): official NIST vectors for keygen, encaps/sign, and decaps/verify.
- **Submission schemes** (McEliece, SNTRUP, NTRU LPRime): official reference vectors for keygen, encaps, and decaps, plus chained 100-round deterministic roundtrips for internal consistency.

The full KAT suite runs as part of the standard test harness:

```bash
cargo test --release
```

### Building & SIMD

```bash
# Release build (all crates)
cargo build --release

# With SIMD acceleration (AVX2, PCLMULQDQ)
RUSTFLAGS="-C target-cpu=native" cargo build --release --features \
  backbone-ml-dsa/simd,backbone-hqc/simd,backbone-mceliece/simd,backbone-sntrup/simd
```

When the `simd` feature is not enabled (or when building without `target-cpu=native`), the scalar fallback is used automatically — zero dependency cost. Backend selection is compile-time (`cfg(target_feature = …)`): building with `-C target-cpu=native` on a CPU that lacks the required features falls back to the scalar path.

#### Constant-time

The SIMD paths are designed for constant-time behavior — no secret-dependent branches, no secret-indexed memory, branchless masking — and every SIMD backend is differentially tested byte-for-byte against its scalar fallback (the AVX2/PCLMULQDQ suites run in both simd-on and simd-off builds).

### Caveats

These implementations have not undergone a formal security audit. As with all cryptographic software, we recommend third-party review before production use. See [SECURITY.md](SECURITY.md) for details.

---

Built with ❤️ by [Backbone](https://backbone.dev)

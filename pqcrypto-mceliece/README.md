# pqcrypto-mceliece

Classic McEliece — code-based Key Encapsulation Mechanism, NIST Round 4 candidate.

A KEM whose security reduces to the hardness of decoding random linear
binary Goppa codes. The oldest and most studied code-based cryptosystem,
with the largest public keys but the smallest ciphertexts among PQC KEMs.
Considered the most conservative choice for long-term security (BSI
recommended).

10 variants: five base parameter sets plus `f` (fast) variants using
field-linear (FFT) key generation:

| Variant | PK bytes | SK bytes | CT bytes |
|---|---|---|---|
| mceliece348864 / f | 261120 | 6452 / 6428 | 128 |
| mceliece460896 / f | 524160 | 13568 / 13536 | 188 |
| mceliece6688128 / f | 1044992 | 13892 / 13860 | 240 |
| mceliece6960119 / f | 1047319 | 13924 / 13892 | 226 |
| mceliece8192128 / f | 1357824 | 14120 / 14088 | 240 |

All variants use GF(2) polynomial multiplication and support both
SHAKE-256 and `#[cfg(feature = "drbg")]` AES-CTR DRBG keygen paths.

## Other Implementations

- **NIST Submission (C)**: [classic.mceliece.org](https://classic.mceliece.org/)
- **classic-mceliece-rust (Rust)**: [Colfenor/classic-mceliece-rust](https://github.com/Colfenor/classic-mceliece-rust) — crate: [`classic-mceliece-rust`](https://crates.io/crates/classic-mceliece-rust)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
- **Go (circl)**: [katzenpost/circl](https://pkg.go.dev/github.com/katzenpost/circl/kem/mceliece)

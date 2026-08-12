# backbone-mceliece

Classic McEliece — code-based Key Encapsulation Mechanism, NIST Round 4 candidate.

A KEM whose security reduces to the hardness of decoding random linear
binary Goppa codes. The oldest and most studied code-based cryptosystem,
with the largest public keys but the smallest ciphertexts among PQC KEMs.
Considered the most conservative choice for long-term security (BSI
recommended).

10 variants: five base parameter sets plus `f` (fast) variants using
field-linear (FFT) key generation:

| Variant | PK bytes | SK bytes | CT bytes |
| --- | --- | --- | --- |
| mceliece348864 / f | 261120 | 6492 | 96 |
| mceliece460896 / f | 524160 | 13608 | 156 |
| mceliece6688128 / f | 1044992 | 13932 | 208 |
| mceliece6960119 / f | 1047319 | 13948 | 194 |
| mceliece8192128 / f | 1357824 | 14120 | 208 |

Key generation expands the 48-byte seed via the NIST AES-256 CTR_DRBG
seedexpander (SP 800-90A), matching the official reference KAT harness.

## Validation

KATs are the official NIST Round 4 submission vectors
(mceliece-kat-20221023). Keygen, encaps, and decaps are validated
byte-for-byte against them for all 10 variants. NIST ACVP vectors not
available (Classic McEliece not yet standardized).

## Other Implementations

- **NIST Submission (C)**: [classic.mceliece.org](https://classic.mceliece.org/)
- **classic-mceliece-rust (Rust)**: [Colfenor/classic-mceliece-rust](https://github.com/Colfenor/classic-mceliece-rust) — crate: [`classic-mceliece-rust`](https://crates.io/crates/classic-mceliece-rust)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
- **Go (circl)**: [katzenpost/circl](https://pkg.go.dev/github.com/katzenpost/circl/kem/mceliece)

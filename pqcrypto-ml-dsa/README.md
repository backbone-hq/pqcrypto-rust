# pqcrypto-ml-dsa

ML-DSA (FIPS 204) — Module-Lattice-Based Digital Signature Standard, formerly known as CRYSTALS-Dilithium.

A signature scheme built on the hardness of Module-LWE and Module-SIS
problems over the ring `R_q = Z_q[x]/(x^n+1)` with `q = 8380417`.
Three parameter sets:

| Variant | Security level | PK bytes | SK bytes | Sig bytes |
|---|---|---|---|---|
| ML-DSA-44 | 2 (128-bit) | 1312 | 2560 | 2420 |
| ML-DSA-65 | 3 (192-bit) | 1952 | 4032 | 3309 |
| ML-DSA-87 | 5 (256-bit) | 2592 | 4896 | 4627 |

Supports both deterministic (pure) and hedged (randomized) signing modes.
Deterministic mode uses a zero `rnd` per the spec.

## Other Implementations

- **NIST Reference (C)**: [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium)
- **RustCrypto (Rust)**: [ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) — crate: [`ml-dsa`](https://crates.io/crates/ml-dsa)
- **libcrux (Rust, formally verified)**: [Cryspen libcrux](https://github.com/cryspen/libcrux)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)

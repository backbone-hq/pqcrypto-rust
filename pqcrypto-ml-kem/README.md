# pqcrypto-ml-kem

ML-KEM (FIPS 203) — Module-Lattice-Based Key Encapsulation Mechanism, formerly known as CRYSTALS-Kyber.

A KEM built on the hardness of the Module-LWE problem over the ring
`R_q = Z_q[x]/(x^n+1)` with `q = 3329`. Three parameter sets provide
NIST security levels 1, 3, and 5:

| Variant | K | eta1 | eta2 | du | dv | PK bytes | SK bytes | CT bytes |
|---|---|---|---|---|---|---|---|---|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 | 1632 | 768 |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 | 3168 | 1568 |

Includes both the default SHAKE-256-based PRNG path and an
`#[cfg(feature = "drbg")]` AES-CTR DRBG mode for KAT reproduction.

## Other Implementations

- **NIST Reference (C)**: [pq-crystals/kyber](https://github.com/pq-crystals/kyber)
- **RustCrypto (Rust)**: [ml-kem](https://github.com/RustCrypto/KEMs/tree/master/ml-kem) — crate: [`ml-kem`](https://crates.io/crates/ml-kem)
- **libcrux (Rust, formally verified)**: [Cryspen libcrux](https://github.com/cryspen/libcrux)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)

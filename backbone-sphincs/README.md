# backbone-sphincs

SPHINCS+ (FIPS 205), now standardized as SLH-DSA — Stateless Hash-Based Digital Signature Standard.

A stateless hash-based signature scheme whose security depends only on
the security of the underlying hash function, not on any lattice or
number-theoretic assumptions. Uses a hypertree of Winternitz one-time
signatures built on top of a Merkle tree.

12 variants: combinations of hash function (SHA-256 or SHAKE), speed/size
trade-off (fast `f` or small `s`), and security level (128, 192, 256):

| Variant | PK bytes | SK bytes | Sig bytes |
| --- | --- | --- | --- |
| SHAKE-128s | 32 | 64 | 7856 |
| SHAKE-128f | 32 | 64 | 17088 |
| SHAKE-192s | 48 | 96 | 16224 |
| SHAKE-192f | 48 | 96 | 35664 |
| SHAKE-256s | 64 | 128 | 29792 |
| SHAKE-256f | 64 | 128 | 49856 |
| SHA2-128s | 32 | 64 | 7856 |
| SHA2-128f | 32 | 64 | 17088 |
| SHA2-192s | 48 | 96 | 16224 |
| SHA2-192f | 48 | 96 | 35664 |
| SHA2-256s | 64 | 128 | 29792 |
| SHA2-256f | 64 | 128 | 49856 |

## Validation

Tested against NIST ACVP vectors (FIPS 205).

## Other Implementations

- **NIST Reference (C)**: [sphincs/sphincsplus](https://github.com/sphincs/sphincsplus)
- **RustCrypto (Rust)**: [slh-dsa](https://github.com/RustCrypto/signatures/tree/master/slh-dsa) — crate: [`slh-dsa`](https://crates.io/crates/slh-dsa)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)

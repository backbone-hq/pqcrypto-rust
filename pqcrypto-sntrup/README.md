# pqcrypto-sntrup

Streamlined NTRU Prime — lattice-based Key Encapsulation Mechanism, NIST Round 4 candidate.

A KEM using the "Prime" design principle: ring arithmetic over
`Z_q[x]/(x^p - x - 1)` with carefully chosen parameters to eliminate
decryption failures entirely. Designed by Bernstein, Chuengsatiansup,
Lange, and van Vredendaal.

Single widely-deployed variant:

| Variant | p | q | PK bytes | SK bytes | CT bytes |
|---|---|---|---|---|---|
| sntrup761 | 761 | 4591 | 1218 | 1763 | 1047 |

No official NIST KAT vectors exist — validation relies on self-consistency
(roundtrip, determinism) and cross-validation via liboqs. An
`#[cfg(feature = "drbg")]` AES-CTR DRBG mode is available but no published
reference vectors use this variant's PRNG.

## Other Implementations

- **Official Reference (C)**: [ntruprime.cr.yp.to](https://ntruprime.cr.yp.to/)
- **liboqs (C)**: [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean (C)**: [PQClean/PQClean](https://github.com/PQClean/PQClean)
- **streamlined-ntru-prime (Rust, outdated)**: [mberry/Streamlined-NTRU-Prime](https://github.com/mberry/Streamlined-NTRU-Prime) — crate: [`streamlined-ntru-prime`](https://crates.io/crates/streamlined-ntru-prime)

# backbone-pqcrypto-internals

Shared internal utilities for the `backbone-*` post-quantum cryptography
workspace. This crate is a dependency of every other backbone crate and is
not intended as an application-facing API.

Provides:

- **KAT helpers** — parsing and execution of NIST Known Answer Test vectors
- **Secret memory** — zeroizing wrappers (`SecretVec`, `SecretArray`) for
  secret material
- **Tree encoding** — address-encoding utilities for hash-based schemes
- **Shared errors** — the `PqcError` trait and uniform error plumbing
- **Support modules** — constant-time comparison/selection, Karatsuba
  multiplication, NIST seed expansion, OID handling, and NTRU ring helpers

## License

Apache-2.0 — see [LICENSE](LICENSE).

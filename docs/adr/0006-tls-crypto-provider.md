# 0006. `aws-lc-rs` as the TLS crypto provider

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Resguardo talks to the providers over TLS with `rustls` (through `reqwest`). `rustls` does not implement cryptography itself: it delegates to a *crypto provider*. Two are maintained for it:

| | `ring` | `aws-lc-rs` |
| --- | --- | --- |
| Latest release (crates.io, 2026-11-25) | 0.17.14, March 2025 | 1.19.0, October 2026 |
| Default in `rustls` and `reqwest` | No | Yes |
| Hybrid post-quantum key exchange (X25519MLKEM768) | Not confirmed | Yes |
| FIPS 140-3 validated build | No | Optional (`fips` feature) |
| Build cost | Small C and assembly | A large C library; first build takes minutes |
| Licenses | Allowed by `deny.toml` | Allowed by `deny.toml` |

Resguardo is a security product: prompts sent through it may contain sensitive data, and TLS is what protects them on the wire to the provider.

## Decision

Use **`aws-lc-rs`** as the `rustls` crypto provider.

- It is the default, so the configuration is the most tested path, not a custom one.
- It is actively released, which matters for a dependency that handles every byte sent to the provider.
- Its hybrid post-quantum key exchange protects recorded traffic against later decryption ("harvest now, decrypt later"). Whether it is negotiated by default is checked against the `rustls` documentation in M1.5 and covered by a test there.
- A FIPS build stays possible without changing crates.

## Consequences

- The first build is slower, especially on older machines; incremental builds are not affected.
- Building needs a C compiler. The README lists it.
- `ring` must not appear in the dependency tree for TLS. M1.5 checks this with `cargo tree -i ring`.
- Audit log signing (ADR 0003) is a separate decision, taken in M5; it may use `ed25519-dalek` or `aws-lc-rs`.

## Verification (M1.5, 2026-11-25)

- `reqwest` 0.13's `rustls` feature selects `aws-lc-rs` and `rustls-platform-verifier` (the operating system's certificate verifier).
- `reqwest` turns off the default features of `rustls`, including `prefer-post-quantum`. Without it, X25519MLKEM768 is offered **last**, so handshakes would normally use classical X25519. `resguardo-egress` depends on `rustls` directly only to turn that feature back on, and a unit test checks that X25519MLKEM768 is the first key exchange group offered.
- `ring` is banned in `deny.toml`, so it cannot enter the dependency tree unnoticed.
- Building needs a C compiler; CMake is not required (checked on macOS).

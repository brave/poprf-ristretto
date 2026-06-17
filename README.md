# poprf-ristretto

[![CI](https://github.com/brave/poprf-ristretto/actions/workflows/ci.yml/badge.svg)](https://github.com/brave/poprf-ristretto/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A Rust implementation of the **Partially-Oblivious Pseudorandom Function
(POPRF)** from [RFC 9497] over the `ristretto255-SHA512` ciphersuite.

[RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497.html

POPRF lets a client and a server jointly compute `F(skS, input, info)` where:

- the client learns the output but reveals nothing about `input` to the server,
- the server uses its secret key `skS` and a public `info` tag chosen per call,
- the client receives a verifiable DLEQ proof binding the output to a
  previously committed public key `pkS`.

This is the building block for partition-able privacy-preserving tokens
(e.g. Privacy Pass, anonymous-credential issuance, attribute-bound rate
limiting). It is the *partially-oblivious* mode — the `info` string is
public and chosen at evaluation time — distinct from plain OPRF (no
`info`) and VOPRF (verifiable, no `info`).

## Workspace layout

This repository is a Cargo workspace with three crates:

| Crate | Purpose | Audience |
|-------|---------|----------|
| [`poprf-ristretto`](./poprf-ristretto) | Core RFC 9497 protocol, no-std capable | Rust callers |
| [`poprf-ristretto-ffi`](./poprf-ristretto-ffi) | C ABI `cdylib` + generated header | Any FFI-capable runtime (C, C++, Go, Python, …) |
| [`poprf-ristretto-wasm`](./poprf-ristretto-wasm) | `wasm-bindgen` bindings | Browser / Node.js / bundler consumers |

Each crate has its own README with usage, build, and consumption instructions.

## Status

**0.1.0 — pending audit.** All RFC 9497 Appendix A test
vectors for the `ristretto255-SHA512` POPRF mode pass. The security
contract (pseudorandomness, obliviousness, verifiability, info-binding)
and constant-time discipline are documented in the crate-level rustdoc;
run `cargo doc --open -p poprf-ristretto`.

## Quick start

```rust
use poprf_ristretto::{PoprfClient, PoprfServer};
use rand_core::OsRng;

// Server: generate a long-lived key pair.
let server = PoprfServer::generate(&mut OsRng);
let client = PoprfClient::new(server.public_key());

let input = b"my secret input";
let info  = b"public context bound into output";

// Client: blind the input.
let (state, blinded) = client.blind(input, info, &mut OsRng)?;

// Server: blind-evaluate.
let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info)?;

// Client: verify proof and finalize. Server learned nothing about `input`.
let output = client.finalize(input, &state, &evaluated, &blinded, &proof, info)?;
```

A runnable version is at
[`poprf-ristretto/examples/poprf_handshake.rs`](./poprf-ristretto/examples/poprf_handshake.rs).
The batched API (`blind_evaluate_batch` / `finalize_batch`) and the full
reference are in the crate-level rustdoc.

## Building

```sh
cargo build --workspace
cargo test  --workspace
```

Workspace developer tooling (lint, fmt, header drift check, release
builds, publish dry-run) is in the [`Makefile`](./Makefile); see the
file header for the full target list.

## License

Licensed under either of [Apache-2.0](./LICENSE-APACHE) or
[MIT](./LICENSE-MIT) at your option.

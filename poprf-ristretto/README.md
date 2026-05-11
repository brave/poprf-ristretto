# poprf-ristretto

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Pure-Rust implementation of the **Partially-Oblivious Pseudorandom
Function (POPRF)** protocol over the `ristretto255-SHA512` ciphersuite,
as specified in [RFC 9497] §3.3.3 and §4.1. All RFC 9497 Appendix A test
vectors for POPRF/ristretto255-SHA512 pass.

[RFC 9497]: https://www.rfc-editor.org/rfc/rfc9497

`#![no_std]`-capable with the `alloc` feature (enabled by default via
`std`); `#![forbid(unsafe_code)]`. For C ABI bindings see
[`poprf-ristretto-ffi`](../poprf-ristretto-ffi); for WebAssembly
bindings see [`poprf-ristretto-wasm`](../poprf-ristretto-wasm).

## Quick start

```rust
use poprf_ristretto::{PoprfClient, PoprfServer};
use rand_core::OsRng;

let server = PoprfServer::generate(&mut OsRng);
let client = PoprfClient::new(server.public_key());

let input = b"my secret input";
let info  = b"public context bound into output";

let (state, blinded)   = client.blind(input, info, &mut OsRng).unwrap();
let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();
let output = client
    .finalize(input, &state, &evaluated, &blinded, &proof, info)
    .expect("proof verified");

// Server-side offline evaluation must agree.
assert_eq!(output, server.evaluate(input, info).unwrap());
```

For the batched API (one DLEQ proof over `N` tokens), see
`PoprfServer::blind_evaluate_batch` and `PoprfClient::finalize_batch`.

A runnable example is at
[`examples/poprf_handshake.rs`](./examples/poprf_handshake.rs):

```sh
cargo run --example poprf_handshake
```

## Reference

The full API surface, wire-format table, Cargo feature matrix, and
security contract are in the crate-level rustdoc; run
`cargo doc --open -p poprf-ristretto`.

This crate has **not** yet been audited.

## Building

```sh
cargo build
cargo test
cargo bench   # criterion; HTML reports in target/criterion/
```

## License

Licensed under either of [Apache-2.0](./LICENSE-APACHE) or
[MIT](./LICENSE-MIT) at your option.

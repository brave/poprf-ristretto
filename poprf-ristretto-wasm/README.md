# poprf-ristretto-wasm

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`wasm-bindgen` bindings for [`poprf-ristretto`](../poprf-ristretto) —
the RFC 9497 POPRF over `ristretto255-SHA512`. Use from a browser,
Node.js, or any JavaScript runtime by building with [`wasm-pack`].

[`wasm-pack`]: https://rustwasm.github.io/wasm-pack/

## API

**Client-side batched** POPRF operations — two free functions:

| JS name | Direction |
|---------|-----------|
| `blindBatch(publicKeyB64, inputs, info)` | client blind |
| `finalizeBatch(publicKeyB64, inputs, states, blindedMessages, evaluatedElements, proof, info)` | proof verify + unblind |

Wire-format bytes are passed as base64 strings; per-token preimages and
`info` are `Uint8Array` / raw bytes. Errors are thrown as JS `Error`s.

Server-side operations (key generation, `BlindEvaluate`, offline
`Evaluate`) are not exposed; use
[`poprf-ristretto-ffi`](../poprf-ristretto-ffi) (C ABI) or the core
[`poprf-ristretto`](../poprf-ristretto) Rust crate on the server.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

From the workspace root:

```sh
make wasm         # wasm-pack build --target bundler  → poprf-ristretto-wasm/pkg/
make wasm-nodejs  # wasm-pack build --target nodejs   → poprf-ristretto-wasm/pkg-node/
```

Each output directory contains `package.json`, JS glue, TypeScript
declarations, and the `.wasm` binary, importable as a local package.

The wasm crate depends on `poprf-ristretto` with `default-features =
false` plus `["std", "fast-dleq"]`; the core crate's
`precomputed-tables` feature is **not** enabled, keeping the wasm
binary smaller at the cost of slower base-point scalar multiplication.
Edit [`Cargo.toml`](./Cargo.toml) to add it back if size is not a
concern.

## Usage

### Browser / bundler

After `make wasm`, import from the generated `pkg/` directory:

```js
import init, { blindBatch, finalizeBatch } from "./pkg/poprf_ristretto_wasm.js";

await init();

const info  = new TextEncoder().encode("example-context");
const input = new TextEncoder().encode("user-identifier");

// 1) Blind one or more inputs.
const { states, blindedMessages } = blindBatch(
  serverPublicKeyB64,
  [input],
  info,
);

// 2) Send `blindedMessages[i]` to the server. The server returns
//    `evaluatedElements[i]` (base64) and a single batched DLEQ `proof`.

// 3) Verify the proof and unblind.
const outputs = finalizeBatch(
  serverPublicKeyB64,
  [input],
  states,
  blindedMessages,
  evaluatedElements,
  proof,
  info,
);
// outputs[i] is the base64-encoded 64-byte POPRF output for input i.
```

### Node.js

After `make wasm-nodejs`, require from the generated `pkg-node/` directory:

```js
const { blindBatch, finalizeBatch } = require("./pkg-node/poprf_ristretto_wasm.js");
// no init() call needed for the nodejs target
```

## Troubleshooting

### `wasm-bindgen` CLI version pinning

The `wasm-bindgen` CLI must match the `wasm-bindgen` crate version pinned
in `Cargo.lock`. A mismatch causes `wasm-pack` to fail with
"`error: failed to generate bindings`". Install the CLI at the exact
pinned version:

```sh
WBVER=$(grep -A1 'name = "wasm-bindgen"' Cargo.lock | grep version | head -1 | sed 's/.*= "//;s/"//')
cargo install wasm-bindgen-cli --version "$WBVER" --force
```

### `+reference-types` rustflag

`wasm-bindgen` ≥ 0.2.100 requires the WebAssembly **reference-types**
proposal so it can emit its externref table management functions
(`__externref_table_alloc` / `__externref_table_dealloc`). Without this
the linker dead-code-eliminates those symbols and the build fails with:

```
error: failed to find the __wbindgen_externref_table_dealloc function
```

The flag is set in this workspace's `.cargo/config.toml`. If you build
this crate from a **parent** workspace that also sets
`[build] rustflags = ...`, mirror the override there:

```toml
[target.wasm32-unknown-unknown]
rustflags = ["-C", "target-feature=+reference-types"]
```

## License

Licensed under either of [Apache-2.0](./LICENSE-APACHE) or
[MIT](./LICENSE-MIT) at your option.

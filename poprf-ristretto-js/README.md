# poprf-ristretto-js

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Pure-JavaScript client for the RFC 9497 POPRF over `ristretto255-SHA512`,
with the same API and wire format as
[`@brave/poprf-ristretto-wasm`](../poprf-ristretto-wasm). The protocol is done by
[`@noble/curves`](https://github.com/paulmillr/noble-curves) (`ristretto255_oprf.poprf`);
this package only adds the wasm package's encoding, state layout and input validation.

Use it where WebAssembly is unavailable (e.g. V8 `--jitless`, which removes
`WebAssembly` entirely), or where 16 KB gzip of JS beats ~54 KB of wasm.

## API

| JS name | Direction |
|---------|-----------|
| `blindBatch(publicKeyB64, inputs, info)` | client blind |
| `finalizeBatch(publicKeyB64, inputs, states, blindedMessages, evaluatedElements, proof, info)` | proof verify + unblind |

Same names, argument order and types as the wasm package; `test/contract.ts` fails
the type-check if the two ever drift. Wire-format bytes are canonical padded base64
strings; inputs and `info` are `Uint8Array`. A state is base64 `blind ‖ tweakedKey`
(64 bytes), so states from one package can be finalized by the other.

Server-side operations are not exposed, as in the wasm package.

```js
import { blindBatch, finalizeBatch } from "@brave/poprf-ristretto-js";

const info = new TextEncoder().encode("example-context");
const input = new TextEncoder().encode("user-identifier");

const { states, blindedMessages } = blindBatch(serverPublicKeyB64, [input], info);
// Send blindedMessages to the server; it returns evaluatedElements and one batched proof.
const outputs = finalizeBatch(serverPublicKeyB64, [input], states, blindedMessages, evaluatedElements, proof, info);
// outputs[i] is the base64-encoded 64-byte POPRF output for input i.
```

No `init()` is needed.

## Differences from the wasm package

- **Errors are `Error`s**, not bare strings. Messages keep the wasm prefixes where the
  check is ours (`public_key base64: …`, `finalize_batch: …`) but are not API: rely on
  whether a call throws, not on the text.
- **Stricter inputs**: `inputs` and `info` must be `Uint8Array`s and the base64
  arguments strings (wasm coerces array-likes: inputs through `new Uint8Array(value)`,
  `info` through `TypedArray.set`). On an empty batch `info` is length-checked and a key
  whose tweaked key is the identity is rejected (wasm only decodes the key there), and a
  state with a zero blind is rejected (wasm accepts it and returns a meaningless output).
- **Not constant-time.** noble uses JS `BigInt`, unlike the core crate's documented
  constant-time discipline. Client secrets (the per-input blinds, and the inputs via
  hash-to-curve) go through it.

## Performance

`blindBatch` + `finalizeBatch` for 30 inputs, warm median ms (2026-10-28, x86-64 Linux):

| | Chromium 154 | Firefox 158 | WebKitGTK 2.52 | Chromium-based, V8 `--jitless` |
|---|---|---|---|---|
| wasm | 11.0 | 13.5 | 18.9 | fails: no `WebAssembly` |
| this package | 27.4 | 84.0 | 66.0 | 134 |

## Build and test

From the workspace root:

```sh
make js-test     # npm ci, tsc --noEmit, node --test; builds pkg-node/ for the interop tests
make js-tarball  # npm pack (prepack compiles src/ to dist/)
```

The tests run the RFC 9497 vectors from `../poprf-ristretto/tests/vectors`, the
client-side cases of the Rust `tests/negative.rs`, and round trips against the wasm
package (the Rust client) in both directions. Requires Node ≥ 24 (native TypeScript test files).

## License

Licensed under either of [Apache-2.0](./LICENSE-APACHE) or
[MIT](./LICENSE-MIT) at your option.

# poprf-ristretto-ffi

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

C ABI bindings for [`poprf-ristretto`](../poprf-ristretto) — the RFC
9497 POPRF over `ristretto255-SHA512`. Builds as a `cdylib` (and `rlib`)
and ships a [cbindgen]-generated C header.

Usable from C, C++, and any runtime that can call C functions through
its own FFI (e.g. Go via cgo, Python via cffi/ctypes).

[cbindgen]: https://github.com/mozilla/cbindgen

## Scope

**Server-side** POPRF surface plus the wire-format helpers a client needs
to deserialize what the server sent:

- Keys: derive `SecretKey` from a seed, encode/decode either key as
  base64, derive `PublicKey` from `SecretKey`.
- Protocol: `poprf_blind_evaluate_batch` (batched DLEQ proof) and
  `poprf_evaluate` (offline evaluation).
- Wire types: decode `BlindedElement` from base64; encode
  `EvaluatedElement`, `Proof`, `PoprfOutput` to base64.
- Output comparison: constant-time `poprf_output_eq_base64`.

Client-side blinding and `Finalize` are not exposed via C ABI; use the
[`poprf-ristretto-wasm`](../poprf-ristretto-wasm) crate from JavaScript
clients, or call the core [`poprf-ristretto`](../poprf-ristretto) Rust
crate directly.

## Object model and ownership

All POPRF types are opaque handles owned by Rust. Every constructor
returns `*mut T`; every type has a matching `poprf_*_destroy` (safe to
call with `NULL`). Owned `char *` strings returned by `*_encode_base64`
and `poprf_last_error_message` are freed with `poprf_c_char_destroy`.

| Handle | Produced by |
|--------|-------------|
| `SecretKey *`        | `poprf_secret_key_from_seed`, `poprf_secret_key_decode_base64` |
| `PublicKey *`        | `poprf_public_key_from_secret` |
| `BlindedElement *`   | `poprf_blinded_element_decode_base64` |
| `EvaluatedElement *` | `poprf_blind_evaluate_batch` (one per token) |
| `Proof *`            | `poprf_blind_evaluate_batch` |
| `PoprfOutput *`      | `poprf_evaluate` |

No FFI function other than the destructors takes ownership of or mutates
its handle arguments. Higher-level bindings should wrap each
constructor/destructor pair in their host language's RAII / finalizer
idiom (e.g. `std::unique_ptr` with a custom deleter in C++,
`runtime.SetFinalizer` in Go).

## Error handling

Failing functions return `NULL` (pointer-returning) or non-zero (int-
returning). The cause is exposed via a thread-local last-error slot:

```c
char *err = poprf_last_error_message();
if (err != NULL) {
    fprintf(stderr, "poprf: %s\n", err);
    poprf_c_char_destroy(err);
}
```

## Thread safety

- Operations on a handle (encoding, deriving the public key,
  blind-evaluate, evaluate) are `Send + Sync`.
- Constructors that need randomness use a CSPRNG seeded from the OS
  (`OsRng`); there is no global mutable state.
- `LAST_ERROR` is thread-local — errors set on one thread are not visible
  on another.

Do not call `poprf_*_destroy` on a handle while another thread is using it.

## Building

```sh
cargo build --release -p poprf-ristretto-ffi
```

The binding crate depends on `poprf-ristretto` with `default-features =
false` plus `["std", "fast-dleq"]`; the core crate's
`precomputed-tables` feature is **not** enabled, keeping the cdylib
smaller at the cost of slower base-point scalar multiplication. Edit
[`Cargo.toml`](./Cargo.toml) to add it back if size is not a concern.

Produces:

| Platform | Output |
|----------|--------|
| Linux    | `target/release/libpoprf_ristretto_ffi.so` |
| macOS    | `target/release/libpoprf_ristretto_ffi.dylib` |
| Windows  | `target/release/poprf_ristretto_ffi.dll` |

Or from the workspace root: `make ffi-release`.

### C header

The C header is checked in at
[`include/poprf_ristretto_ffi.h`](./include/poprf_ristretto_ffi.h),
regenerated from `src/lib.rs` via `cbindgen`:

```sh
cargo install cbindgen   # one-time
make headers             # from workspace root
```

CI runs `make check-headers`, which regenerates into a tempfile and diffs
against the committed copy. Any drift fails the build.

Header verification:

```sh
gcc -Wall -Wextra -Wpedantic -c -x c   include/poprf_ristretto_ffi.h -o /dev/null
g++ -Wall -Wextra -Wpedantic -c -x c++ include/poprf_ristretto_ffi.h -o /dev/null
```

## Usage from C

End-to-end server-side example. The client side (blinding and
`Finalize`) is exposed via the wasm crate or the core Rust crate.

```c
#include <stdio.h>
#include <stdint.h>
#include "poprf_ristretto_ffi.h"

int main(void) {
    const uint8_t seed[32] = { /* 32 bytes of CSPRNG output */ };
    const uint8_t info[]   = "example-context";

    /* 1. Derive a long-lived secret key from a 32-byte seed. */
    SecretKey *sk = poprf_secret_key_from_seed(
        seed, sizeof seed,
        info, sizeof info - 1);
    if (sk == NULL) goto err;

    /* 2. Decode a base64-encoded BlindedElement received from the client. */
    const char *blinded_b64 = "...";  /* received over the wire */
    BlindedElement *bl = poprf_blinded_element_decode_base64(
        (const uint8_t *)blinded_b64,
        /* len = */ 44);              /* 32-byte element → 44 base64 chars */
    if (bl == NULL) goto err;

    /* 3. Batched blind-evaluate (one entry here). */
    const BlindedElement *bl_arr[1] = { bl };
    EvaluatedElement *out_eval[1]   = { NULL };
    Proof            *out_proof     = NULL;
    int rc = poprf_blind_evaluate_batch(
        sk, bl_arr, /* n = */ 1,
        info, sizeof info - 1,
        out_eval, &out_proof);
    if (rc != 0) goto err;

    /* 4. Encode results for transmission back to the client. */
    char *eval_b64  = poprf_evaluated_element_encode_base64(out_eval[0]);
    char *proof_b64 = poprf_proof_encode_base64(out_proof);
    if (eval_b64 == NULL || proof_b64 == NULL) goto err;

    printf("eval=%s\nproof=%s\n", eval_b64, proof_b64);

    /* 5. Cleanup. */
    poprf_c_char_destroy(eval_b64);
    poprf_c_char_destroy(proof_b64);
    poprf_proof_destroy(out_proof);
    poprf_evaluated_element_destroy(out_eval[0]);
    poprf_blinded_element_destroy(bl);
    poprf_secret_key_destroy(sk);
    return 0;

err: {
    char *msg = poprf_last_error_message();
    if (msg != NULL) {
        fprintf(stderr, "poprf: %s\n", msg);
        poprf_c_char_destroy(msg);
    }
    return 1;
}
}
```

See [`tests/integration_test.rs`](./tests/integration_test.rs) for the
Rust-side equivalent exercising the full happy-path FFI surface.

## Safety

This crate is the only part of the workspace that uses `unsafe`. Every
`pub unsafe extern "C" fn` carries a `# Safety` doc block stating the
preconditions for its raw-pointer and length-prefixed-buffer arguments;
see the per-function rustdoc (`cargo doc --open -p poprf-ristretto-ffi`).

Panic safety: the workspace builds with `panic = "abort"` in release
mode, so a Rust panic terminates the process rather than unwinding into
the C caller (which would be UB).

## License

Licensed under either of [Apache-2.0](./LICENSE-APACHE) or
[MIT](./LICENSE-MIT) at your option.

//! Smoke test: end-to-end POPRF round-trip across the wasm-bindgen
//! boundary.
//!
//! Run with:
//!
//!     wasm-pack test --node poprf-ristretto-wasm
//!
//! The Rust test suite of the core crate already exercises the protocol
//! arithmetic. This test specifically targets the `js_sys::Array` /
//! `Uint8Array` / `JsValue` glue in `poprf-ristretto-wasm` — the layer
//! where a regression could land that a `cargo test` would miss.
//!
//! Flow:
//!   1. Deterministic server keypair via `derive_key_pair`.
//!   2. Client side: `blindBatch` on two fixed inputs (Rust → JS Array).
//!   3. Server side (native Rust, not crossing the wasm boundary):
//!      `PoprfServer::blind_evaluate_batch`.
//!   4. Client side: `finalizeBatch` (JS Array → Rust → JS Array).
//!   5. Independent oracle: `PoprfServer::evaluate` on each input.
//!   6. Assert the finalized outputs equal the oracle outputs.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

use poprf_ristretto::{BlindedElement, PoprfServer, derive_key_pair};
use poprf_ristretto_wasm::{blind_batch, finalize_batch};

// No `wasm_bindgen_test_configure!` call: the default runner target is
// Node, which is what `wasm-pack test --node` invokes. We pick Node over
// a headless browser to keep CI free of browser binaries; the test
// exercises no DOM API.

// Deterministic, test-only seed and info. Not security-sensitive; the
// test asserts round-trip identity, not secret-key confidentiality.
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const KEY_INFO: &[u8] = b"poprf-ristretto-wasm-smoke";
const INFO: &[u8] = b"shared-info-string";
const INPUT_A: &[u8] = b"alice's preimage bytes";
const INPUT_B: &[u8] = b"bob's preimage bytes";

fn uint8array_from(bytes: &[u8]) -> js_sys::Uint8Array {
    let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(bytes);
    arr
}

fn js_array_of_inputs() -> js_sys::Array {
    let arr = js_sys::Array::new();
    arr.push(&uint8array_from(INPUT_A));
    arr.push(&uint8array_from(INPUT_B));
    arr
}

fn array_field(obj: &JsValue, key: &str) -> js_sys::Array {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .expect("field present")
        .dyn_into::<js_sys::Array>()
        .expect("field is Array")
}

fn array_to_b64_strings(arr: &js_sys::Array) -> Vec<String> {
    (0..arr.length())
        .map(|i| arr.get(i).as_string().expect("element is string"))
        .collect()
}

#[wasm_bindgen_test]
fn round_trip_blind_eval_finalize() {
    // 1. Deterministic keypair.
    let (sk, pk) = derive_key_pair(&SEED, KEY_INFO).expect("derive_key_pair");
    let pk_b64 = B64.encode(pk.to_bytes());

    // 2. Client blind: produces { states, blindedMessages }.
    let inputs = js_array_of_inputs();
    let blind_out = blind_batch(&pk_b64, &inputs, INFO).expect("blind_batch");
    let states_arr = array_field(&blind_out, "states");
    let blindeds_arr = array_field(&blind_out, "blindedMessages");

    // 3. Server side, native Rust: reconstruct BlindedElements from
    //    the base64 strings the wasm shim produced.
    let blindeds_b64 = array_to_b64_strings(&blindeds_arr);
    let blindeds_rust: Vec<BlindedElement> = blindeds_b64
        .iter()
        .map(|s| {
            let bytes = B64.decode(s.as_bytes()).expect("blinded b64");
            BlindedElement::from_bytes(&bytes).expect("BlindedElement::from_bytes")
        })
        .collect();

    let server = PoprfServer::new(sk.clone());
    let mut rng = rand_core::OsRng;
    let (evals, proof) = server
        .blind_evaluate_batch(&mut rng, &blindeds_rust, INFO)
        .expect("blind_evaluate_batch");

    // 4. Client finalize: cross back through the wasm boundary.
    let evals_arr = js_sys::Array::new();
    for e in &evals {
        evals_arr.push(&JsValue::from_str(&B64.encode(e.to_bytes())));
    }
    let proof_b64 = B64.encode(proof.to_bytes());
    let finalized = finalize_batch(
        &pk_b64,
        &inputs,
        &states_arr,
        &blindeds_arr,
        &evals_arr,
        &proof_b64,
        INFO,
    )
    .expect("finalize_batch");

    let finalized_b64 = array_to_b64_strings(&finalized);
    assert_eq!(finalized_b64.len(), 2, "two outputs expected");

    // 5+6. Oracle and equality check.
    let oracle_a = server.evaluate(INPUT_A, INFO).expect("evaluate A");
    let oracle_b = server.evaluate(INPUT_B, INFO).expect("evaluate B");
    let oracle_a_b64 = B64.encode(oracle_a.as_bytes());
    let oracle_b_b64 = B64.encode(oracle_b.as_bytes());

    assert_eq!(finalized_b64[0], oracle_a_b64, "client A == oracle A");
    assert_eq!(finalized_b64[1], oracle_b_b64, "client B == oracle B");
}

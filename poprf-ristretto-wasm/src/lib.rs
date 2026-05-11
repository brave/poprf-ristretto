//! `wasm-bindgen` bindings for the client-side batched POPRF surface
//! ([`blind_batch`] / [`finalize_batch`]).
//!
//! Array parameters use `js_sys::Array` rather than `Vec<js_sys::Uint8Array>`
//! to avoid the wasm-bindgen externref vector transform, which requires a
//! CLI version with externref table support.

#![forbid(unsafe_code)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand_core::OsRng;
use wasm_bindgen::prelude::*;

use poprf_ristretto::{
    BlindedElement, EvaluatedElement, PoprfBlindState, PoprfClient, PoprfOutput, Proof, PublicKey,
};

fn js_err(msg: impl Into<String>) -> JsValue {
    JsValue::from_str(&msg.into())
}

/// Extract bytes from a JS Array element that is a Uint8Array.
fn uint8array_to_vec(val: &JsValue) -> Result<Vec<u8>, JsValue> {
    let arr = js_sys::Uint8Array::new(val);
    Ok(arr.to_vec())
}

/// Batched blind: returns one base64-encoded `BlindedElement` per input.
///
/// `inputs` is a JS `Array` of `Uint8Array` — each is a per-token preimage
/// chosen by the client (typically 32–64 random bytes). `info` is the POPRF
/// `info` parameter; both peers must agree on it out-of-band.
///
/// Returns an object with shape `{ states: string[], blindedMessages: string[] }`
/// where each `states[i]` is a base64-encoded 64-byte [`PoprfBlindState`] and
/// each `blindedMessages[i]` is a base64-encoded 32-byte `BlindedElement`.
#[wasm_bindgen(js_name = blindBatch)]
pub fn blind_batch(
    public_key_b64: &str,
    inputs: &js_sys::Array,
    info: &[u8],
) -> Result<JsValue, JsValue> {
    let pk_bytes = B64
        .decode(public_key_b64.as_bytes())
        .map_err(|e| js_err(format!("public_key base64: {e}")))?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|e| js_err(format!("PublicKey: {e}")))?;
    let client = PoprfClient::new(pk);

    let states_b64 = js_sys::Array::new();
    let blindeds_b64 = js_sys::Array::new();
    let mut rng = OsRng;

    let n = inputs.length();
    for i in 0..n {
        let elem = inputs.get(i);
        let input = uint8array_to_vec(&elem)?;
        let (state, blinded) = client
            .blind(&input, info, &mut rng)
            .map_err(|e| js_err(format!("blind: {e}")))?;
        states_b64.push(&JsValue::from_str(&B64.encode(state.to_bytes())));
        blindeds_b64.push(&JsValue::from_str(&B64.encode(blinded.to_bytes())));
    }

    let out = js_sys::Object::new();
    js_sys::Reflect::set(&out, &JsValue::from_str("states"), &states_b64)?;
    js_sys::Reflect::set(&out, &JsValue::from_str("blindedMessages"), &blindeds_b64)?;
    Ok(out.into())
}

/// Batched finalize: verifies the server's DLEQ proof and unblinds each
/// `EvaluatedElement` into a 64-byte [`PoprfOutput`].
///
/// All array parameters must have the same length `N`.
/// - `inputs`: JS `Array` of `Uint8Array` (the original preimage bytes from blind).
/// - `states_b64`, `blindeds_b64`, `evaluateds_b64`: JS `Array` of base64 strings.
/// - `proof_b64`: base64-encoded batch DLEQ proof.
/// - `info`: POPRF info parameter (UTF-8 bytes).
///
/// Returns a JS `Array` of `N` base64-encoded 64-byte [`PoprfOutput`]s.
#[wasm_bindgen(js_name = finalizeBatch)]
pub fn finalize_batch(
    public_key_b64: &str,
    inputs: &js_sys::Array,
    states_b64: &js_sys::Array,
    blindeds_b64: &js_sys::Array,
    evaluateds_b64: &js_sys::Array,
    proof_b64: &str,
    info: &[u8],
) -> Result<js_sys::Array, JsValue> {
    let pk_bytes = B64
        .decode(public_key_b64.as_bytes())
        .map_err(|e| js_err(format!("public_key base64: {e}")))?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|e| js_err(format!("PublicKey: {e}")))?;
    let client = PoprfClient::new(pk);

    let n = inputs.length() as usize;
    if states_b64.length() as usize != n
        || blindeds_b64.length() as usize != n
        || evaluateds_b64.length() as usize != n
    {
        return Err(js_err("finalize_batch: array length mismatch"));
    }

    let input_vecs: Result<Vec<Vec<u8>>, JsValue> = (0..n as u32)
        .map(|i| uint8array_to_vec(&inputs.get(i)))
        .collect();
    let input_vecs = input_vecs?;
    let input_refs: Vec<&[u8]> = input_vecs.iter().map(|v| v.as_slice()).collect();

    let mut states: Vec<PoprfBlindState> = Vec::with_capacity(n);
    let mut blindeds: Vec<BlindedElement> = Vec::with_capacity(n);
    let mut evaluateds: Vec<EvaluatedElement> = Vec::with_capacity(n);

    for i in 0..n {
        let s = states_b64
            .get(i as u32)
            .as_string()
            .ok_or_else(|| js_err("state must be string"))?;
        let s_bytes = B64
            .decode(s.as_bytes())
            .map_err(|e| js_err(format!("state base64: {e}")))?;
        states.push(
            PoprfBlindState::from_bytes(&s_bytes).map_err(|e| js_err(format!("state: {e}")))?,
        );

        let b = blindeds_b64
            .get(i as u32)
            .as_string()
            .ok_or_else(|| js_err("blinded must be string"))?;
        let b_bytes = B64
            .decode(b.as_bytes())
            .map_err(|e| js_err(format!("blinded base64: {e}")))?;
        blindeds.push(
            BlindedElement::from_bytes(&b_bytes).map_err(|e| js_err(format!("blinded: {e}")))?,
        );

        let e = evaluateds_b64
            .get(i as u32)
            .as_string()
            .ok_or_else(|| js_err("evaluated must be string"))?;
        let e_bytes = B64
            .decode(e.as_bytes())
            .map_err(|e| js_err(format!("evaluated base64: {e}")))?;
        evaluateds.push(
            EvaluatedElement::from_bytes(&e_bytes)
                .map_err(|e| js_err(format!("evaluated: {e}")))?,
        );
    }

    let proof_bytes = B64
        .decode(proof_b64.as_bytes())
        .map_err(|e| js_err(format!("proof base64: {e}")))?;
    let proof = Proof::from_bytes(&proof_bytes).map_err(|e| js_err(format!("proof: {e}")))?;

    let outputs: Vec<PoprfOutput> = client
        .finalize_batch(&input_refs, &states, &evaluateds, &blindeds, &proof, info)
        .map_err(|e| js_err(format!("finalize_batch: {e}")))?;

    let arr = js_sys::Array::new();
    for o in outputs {
        arr.push(&JsValue::from_str(&B64.encode(o.as_bytes())));
    }
    Ok(arr)
}

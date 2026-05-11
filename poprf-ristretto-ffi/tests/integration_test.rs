//! Integration test for poprf-ristretto-ffi.
//!
//! Tests the full server-side round-trip through the C ABI:
//!   derive signing key → get public key → blind_evaluate_batch → evaluate → output_eq_base64
//!
//! Client-side blinding uses the poprf-ristretto Rust library directly
//! (same crate the FFI wraps). All assertions verify that the FFI symbols
//! produce consistent, correct results end-to-end.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use poprf_ristretto::{
    BlindedElement, EvaluatedElement as LibEval, PoprfClient, Proof as LibProof, PublicKey,
};
use rand_core::OsRng;

// Re-export the C ABI symbols so they can be called without dlopen.
// Since crate-type = ["cdylib", "rlib"] we can link the rlib in tests.
use poprf_ristretto_ffi::{
    poprf_blind_evaluate_batch, poprf_blinded_element_decode_base64, poprf_blinded_element_destroy,
    poprf_c_char_destroy, poprf_evaluate, poprf_evaluated_element_destroy,
    poprf_evaluated_element_encode_base64, poprf_output_destroy, poprf_output_encode_base64,
    poprf_output_eq_base64, poprf_proof_destroy, poprf_proof_encode_base64,
    poprf_public_key_destroy, poprf_public_key_encode_base64, poprf_public_key_from_secret,
    poprf_secret_key_decode_base64, poprf_secret_key_destroy, poprf_secret_key_encode_base64,
    poprf_secret_key_from_seed,
};

use std::ffi::CStr;
use std::os::raw::c_char;

// ── helpers ─────────────────────────────────────────────────────────────────

unsafe fn take_cstring(ptr: *mut c_char) -> String {
    unsafe {
        assert!(!ptr.is_null(), "unexpected null *c_char");
        let s = CStr::from_ptr(ptr).to_str().unwrap().to_owned();
        poprf_c_char_destroy(ptr);
        s
    }
}

// ── test ─────────────────────────────────────────────────────────────────────

#[test]
fn server_side_round_trip_via_c_abi() {
    let seed: Vec<u8> = (0u8..32).collect();
    let info = b"poprf-ffi-integration-test";
    let input = b"test-token-preimage-bytes-00000000"; // 32 bytes

    unsafe {
        // 1. Derive secret key.
        let sk = poprf_secret_key_from_seed(seed.as_ptr(), seed.len(), info.as_ptr(), info.len());
        assert!(!sk.is_null(), "secret_key_from_seed returned null");

        // 2. Round-trip encode / decode.
        let sk_b64_ptr = poprf_secret_key_encode_base64(sk);
        let sk_b64 = take_cstring(sk_b64_ptr);
        assert!(!sk_b64.is_empty());

        let sk2 = poprf_secret_key_decode_base64(sk_b64.as_ptr(), sk_b64.len());
        assert!(!sk2.is_null(), "secret_key_decode_base64 returned null");
        poprf_secret_key_destroy(sk2);

        // 3. Public key.
        let pk_raw = poprf_public_key_from_secret(sk);
        assert!(!pk_raw.is_null());
        let pk_b64_ptr = poprf_public_key_encode_base64(pk_raw);
        let pk_b64 = take_cstring(pk_b64_ptr);
        assert!(!pk_b64.is_empty());
        poprf_public_key_destroy(pk_raw);

        // 4. Client-side blind (via the Rust library — no FFI blind needed).
        let pk_bytes = B64.decode(&pk_b64).unwrap();
        let pk_obj = PublicKey::from_bytes(&pk_bytes).unwrap();
        let client = PoprfClient::new(pk_obj);
        let (state, blinded) = client.blind(input.as_ref(), info, &mut OsRng).unwrap();

        // Encode the BlindedElement and pass it through the C ABI.
        let blinded_b64 = B64.encode(blinded.to_bytes());
        let be_ptr = poprf_blinded_element_decode_base64(blinded_b64.as_ptr(), blinded_b64.len());
        assert!(
            !be_ptr.is_null(),
            "blinded_element_decode_base64 returned null"
        );

        // 5. Server-side blind_evaluate_batch (C ABI).
        let arr = [be_ptr as *const _];
        let mut out_eval = [std::ptr::null_mut()];
        let mut out_proof = [std::ptr::null_mut()];

        let rc = poprf_blind_evaluate_batch(
            sk,
            arr.as_ptr(),
            1,
            info.as_ptr(),
            info.len(),
            out_eval.as_mut_ptr(),
            out_proof.as_mut_ptr(),
        );
        assert_eq!(rc, 0, "blind_evaluate_batch failed (rc={rc})");

        let eval_ptr = out_eval[0];
        let proof_ptr = out_proof[0];
        assert!(!eval_ptr.is_null());
        assert!(!proof_ptr.is_null());

        let eval_b64 = take_cstring(poprf_evaluated_element_encode_base64(eval_ptr));
        let proof_b64 = take_cstring(poprf_proof_encode_base64(proof_ptr));

        // 6. Client-side finalize (Rust library).
        let eval_bytes = B64.decode(&eval_b64).unwrap();
        let proof_bytes = B64.decode(&proof_b64).unwrap();
        let blinded_bytes = B64.decode(&blinded_b64).unwrap();

        let eval_obj = LibEval::from_bytes(&eval_bytes).unwrap();
        let proof_obj = LibProof::from_bytes(&proof_bytes).unwrap();
        let blinded_obj = BlindedElement::from_bytes(&blinded_bytes).unwrap();

        let pk_obj2 = PublicKey::from_bytes(&pk_bytes).unwrap();
        let client2 = PoprfClient::new(pk_obj2);
        let outputs = client2
            .finalize_batch(
                &[input.as_ref()],
                &[state],
                &[eval_obj],
                &[blinded_obj],
                &proof_obj,
                info,
            )
            .unwrap();
        assert_eq!(outputs.len(), 1);

        let expected_b64 = B64.encode(outputs[0].as_bytes());

        // 7. Server-side evaluate (C ABI) must produce the same output.
        let out_ptr = poprf_evaluate(sk, input.as_ptr(), input.len(), info.as_ptr(), info.len());
        assert!(!out_ptr.is_null(), "poprf_evaluate returned null");

        let encoded = take_cstring(poprf_output_encode_base64(out_ptr));
        assert_eq!(encoded, expected_b64, "evaluate != finalize output");

        // 8. Constant-time compare via C ABI.
        let eq_rc = poprf_output_eq_base64(out_ptr, expected_b64.as_ptr(), expected_b64.len());
        assert_eq!(eq_rc, 1, "output_eq_base64 returned {eq_rc} (expected 1)");

        // 9. Mismatched output must return 0.
        let wrong_b64 = B64.encode([0u8; 64]);
        let ne_rc = poprf_output_eq_base64(out_ptr, wrong_b64.as_ptr(), wrong_b64.len());
        assert_eq!(ne_rc, 0, "output_eq_base64 incorrectly matched wrong value");

        // Clean up.
        poprf_output_destroy(out_ptr);
        poprf_evaluated_element_destroy(eval_ptr);
        poprf_blinded_element_destroy(be_ptr);
        poprf_proof_destroy(proof_ptr);
        poprf_secret_key_destroy(sk);
    }
}

//! Negative-path integration tests for RFC 9497 POPRF/ristretto255-SHA512.
//!
//! These tests cover error conditions that the RFC 9497 Appendix A test
//! vectors do not exercise: wire-format rejection, proof tampering, info
//! mismatch, and the InverseError edge case.

use rand_core::OsRng;

use poprf_ristretto::{
    BlindedElement, Error, EvaluatedElement, PoprfClient, PoprfServer, Proof, PublicKey, SecretKey,
    derive_key_pair,
};

// ── §2.1 DeserializeElement / DeserializeScalar ──────────────────────────────

/// Identity element encoding (all-zeros for ristretto255) must be rejected by
/// DeserializeElement with InputValidation (RFC 9497 §4.1).
#[test]
fn from_bytes_rejects_identity() {
    let zero = [0u8; 32];
    let err = BlindedElement::from_bytes(&zero).unwrap_err();
    assert_eq!(
        err,
        Error::InputValidation,
        "BlindedElement: identity not rejected"
    );

    let err = EvaluatedElement::from_bytes(&zero).unwrap_err();
    assert_eq!(
        err,
        Error::InputValidation,
        "EvaluatedElement: identity not rejected"
    );

    let err = PublicKey::from_bytes(&zero).unwrap_err();
    assert_eq!(
        err,
        Error::InputValidation,
        "PublicKey: identity not rejected"
    );
}

/// SecretKey rejects the zero scalar: a zero secret key would imply
/// pkS = 0·G = O which is forbidden as a public key encoding anyway.
#[test]
fn secret_key_rejects_zero() {
    let zero = [0u8; 32];
    let err = SecretKey::from_bytes(&zero).unwrap_err();
    assert_eq!(err, Error::InputValidation, "SecretKey: zero not rejected");
}

/// RFC 9496 §A.2: "Non-canonical field encodings" — non-canonical field
/// element encodings must be rejected by DeserializeElement.
#[test]
fn from_bytes_rejects_non_canonical_field_element() {
    let bad: [&[u8]; 4] = [
        &[
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ],
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        &[
            0xf3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        &[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    for (i, enc) in bad.iter().enumerate() {
        let err = BlindedElement::from_bytes(enc).unwrap_err();
        assert!(
            matches!(err, Error::Deserialize | Error::InputValidation),
            "vector {i}: expected Deserialize or InputValidation, got {err:?}"
        );
    }
}

/// RFC 9496 §A.2: "Negative field elements" — odd-`s` encodings must be
/// rejected by DeserializeElement.
#[test]
fn from_bytes_rejects_negative_field_element() {
    let mut enc = [0u8; 32];
    enc[0] = 0x01; // s = 1, IS_NEGATIVE → rejected

    let err = BlindedElement::from_bytes(&enc).unwrap_err();
    assert!(
        matches!(err, Error::Deserialize | Error::InputValidation),
        "expected Deserialize or InputValidation, got {err:?}"
    );
}

/// SecretKey::from_bytes must reject scalars outside [0, ℓ-1].
#[test]
fn secret_key_rejects_out_of_range() {
    let bad = [0xffu8; 32];
    let err = SecretKey::from_bytes(&bad).unwrap_err();
    assert_eq!(err, Error::Deserialize, "out-of-range scalar not rejected");
}

/// from_bytes must reject inputs of incorrect length on every wire type.
#[test]
fn from_bytes_rejects_wrong_length() {
    assert_eq!(
        SecretKey::from_bytes(&[0u8; 31]).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        SecretKey::from_bytes(&[0u8; 33]).unwrap_err(),
        Error::Deserialize
    );

    assert_eq!(
        PublicKey::from_bytes(&[0u8; 31]).unwrap_err(),
        Error::Deserialize
    );

    assert_eq!(
        BlindedElement::from_bytes(&[0u8; 31]).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        EvaluatedElement::from_bytes(&[0u8; 33]).unwrap_err(),
        Error::Deserialize
    );

    assert_eq!(
        Proof::from_bytes(&[0u8; 63]).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(
        Proof::from_bytes(&[0u8; 65]).unwrap_err(),
        Error::Deserialize
    );
    assert_eq!(Proof::from_bytes(&[]).unwrap_err(), Error::Deserialize);
}

// ── §2.2.2 VerifyProof — tampered proof / element ────────────────────────────

/// Flipping a single bit in the challenge scalar `c` must cause Finalize to
/// return VerifyError (RFC 9497 §3.3.3).
#[test]
fn finalize_rejects_tampered_proof_c() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"test-info";

    let (state, blinded) = client.blind(b"input", info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();

    let mut proof_bytes = proof.to_bytes();
    proof_bytes[0] ^= 0x01;
    let bad_proof = Proof::from_bytes(&proof_bytes).unwrap_or_else(|_| {
        proof_bytes[0] ^= 0x01;
        proof_bytes[1] ^= 0x02;
        Proof::from_bytes(&proof_bytes).expect("modified proof should deserialize")
    });

    let res = client.finalize(b"input", &state, &evaluated, &blinded, &bad_proof, info);
    assert_eq!(res.unwrap_err(), Error::Verify, "tampered c not detected");
}

/// Flipping a single bit in the response scalar `s` must cause Finalize to
/// return VerifyError.
#[test]
fn finalize_rejects_tampered_proof_s() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"test-info";

    let (state, blinded) = client.blind(b"input", info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();

    let mut proof_bytes = proof.to_bytes();
    proof_bytes[32] ^= 0x01;
    let bad_proof = Proof::from_bytes(&proof_bytes).unwrap_or_else(|_| {
        proof_bytes[32] ^= 0x01;
        proof_bytes[33] ^= 0x02;
        Proof::from_bytes(&proof_bytes).expect("modified proof should deserialize")
    });

    let res = client.finalize(b"input", &state, &evaluated, &blinded, &bad_proof, info);
    assert_eq!(res.unwrap_err(), Error::Verify, "tampered s not detected");
}

/// Replacing the evaluated element with a random point must cause Finalize
/// to return VerifyError — the DLEQ proof won't verify for a different element.
#[test]
fn finalize_rejects_tampered_evaluated_element() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"test-info";

    let (state, blinded) = client.blind(b"input-a", info, &mut OsRng).unwrap();
    let (_, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();

    let (_, blinded2) = client.blind(b"input-b", info, &mut OsRng).unwrap();
    let wrong_eval_bytes = blinded2.to_bytes();
    let wrong_evaluated = EvaluatedElement::from_bytes(&wrong_eval_bytes).unwrap();

    let res = client.finalize(b"input-a", &state, &wrong_evaluated, &blinded, &proof, info);
    assert_eq!(
        res.unwrap_err(),
        Error::Verify,
        "tampered evaluated not detected"
    );
}

// ── §3.3.3 POPRF info binding ─────────────────────────────────────────────────

/// The tweakedKey depends on `info` (RFC 9497 §3.3.3 Blind step).  If the
/// client uses a different `info` than the server used during evaluation, the
/// reconstructed tweakedKey won't match and VerifyProof must fail.
#[test]
fn finalize_rejects_wrong_info() {
    let server = PoprfServer::generate(&mut OsRng);
    let client_wrong = PoprfClient::new(server.public_key());

    let server_info = b"server-info";
    let client_info = b"client-different-info";

    let (state, blinded) = client_wrong
        .blind(b"input", client_info, &mut OsRng)
        .unwrap();
    let (evaluated, proof) = server
        .blind_evaluate(&mut OsRng, &blinded, server_info)
        .unwrap();

    let res = client_wrong.finalize(b"input", &state, &evaluated, &blinded, &proof, client_info);
    assert_eq!(
        res.unwrap_err(),
        Error::Verify,
        "info mismatch not detected"
    );
}

// ── §3.3.3 finalize_batch length checks ──────────────────────────────────────

/// finalize_batch must return LengthMismatch when `inputs` and `states` have
/// different lengths.
#[test]
fn finalize_batch_rejects_mismatched_lengths() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"info";

    let (state, blinded) = client.blind(b"x", info, &mut OsRng).unwrap();
    let (evals, proof) = server
        .blind_evaluate_batch(&mut OsRng, std::slice::from_ref(&blinded), info)
        .unwrap();

    let res = client.finalize_batch(
        &[b"x".as_ref(), b"y".as_ref()],
        &[state],
        &evals,
        &[blinded],
        &proof,
        info,
    );
    assert_eq!(
        res.unwrap_err(),
        Error::LengthMismatch,
        "length mismatch not detected"
    );
}

/// finalize_batch must return LengthMismatch when called with empty slices.
#[test]
fn finalize_batch_rejects_empty() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"info";

    let (_, blinded) = client.blind(b"x", info, &mut OsRng).unwrap();
    let (_, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();

    let res = client.finalize_batch(&[], &[], &[], &[], &proof, info);
    assert_eq!(
        res.unwrap_err(),
        Error::LengthMismatch,
        "empty batch not rejected"
    );
}

/// blind_evaluate_batch must return LengthMismatch on empty input.
#[test]
fn blind_evaluate_batch_rejects_empty() {
    let server = PoprfServer::generate(&mut OsRng);
    let res = server.blind_evaluate_batch(&mut OsRng, &[], b"info");
    assert_eq!(res.unwrap_err(), Error::LengthMismatch);
}

// ── §3.3.3 BlindEvaluate / Evaluate — InverseError ───────────────────────────

/// When `t = skS + m == 0`, both BlindEvaluate and Evaluate must return
/// InverseError (RFC 9497 §3.3.3).
///
/// We construct skS so that skS + m == 0 for a fixed `info` by deriving the
/// expected `m` from the public DST and framedInfo, then negating it via
/// scalar arithmetic exposed through `SecretKey::from_bytes`.
#[test]
fn blind_evaluate_rejects_inverse_zero() {
    use curve25519_dalek::scalar::Scalar;

    let info = b"trigger-inverse";

    // The scalar `m` is HashToScalar(framedInfo) under the DST
    // "HashToScalar-OPRFV1-\x02-ristretto255-SHA512". Replicate the derivation
    // here without using internal crate helpers.
    use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
    use sha2::Sha512;

    let ctx: &[u8] = b"OPRFV1-\x02-ristretto255-SHA512";
    let mut dst = Vec::with_capacity(13 + ctx.len());
    dst.extend_from_slice(b"HashToScalar-");
    dst.extend_from_slice(ctx);

    let len_bytes = (info.len() as u16).to_be_bytes();
    let framed = [b"Info".as_slice(), &len_bytes, info.as_slice()].concat();

    let mut uniform = [0u8; 64];
    let dsts = [dst.as_slice()];
    let mut expander =
        <ExpandMsgXmd<Sha512> as ExpandMsg<'_>>::expand_message(&[&framed], &dsts, 64).unwrap();
    expander.fill_bytes(&mut uniform);
    let m = Scalar::from_bytes_mod_order_wide(&uniform);

    // sk = -m; serialize and reconstitute through SecretKey::from_bytes.
    let sk_scalar = Scalar::ZERO - m;
    let sk_bytes = sk_scalar.to_bytes();
    let sk = SecretKey::from_bytes(&sk_bytes).expect("non-zero secret key");

    let server = PoprfServer::new(sk);
    let dummy_client = PoprfClient::new(server.public_key());
    let (_, blinded) = dummy_client
        .blind(b"any-input", b"other-info", &mut OsRng)
        .unwrap();

    let err = server
        .blind_evaluate(&mut OsRng, &blinded, info)
        .unwrap_err();
    assert_eq!(
        err,
        Error::Inverse,
        "BlindEvaluate: InverseError not raised for t=0"
    );

    let err = server.evaluate(b"any-input", info).unwrap_err();
    assert_eq!(
        err,
        Error::Inverse,
        "Evaluate: InverseError not raised for t=0"
    );
}

// ── §5.1 input length cap (2^16 - 1 bytes) ───────────────────────────────────

/// RFC 9497 §5.1 forbids `input` or `info` values of `2^16 - 1` bytes or
/// longer. Every public entry point that length-prefixes one of these values
/// MUST reject the oversized case with [`Error::InputTooLong`] rather than
/// silently truncating the 2-byte length prefix.
#[test]
fn rejects_oversized_input_and_info() {
    // 2^16 - 1 bytes is the smallest *forbidden* size per RFC 9497 §5.1.
    let too_long = vec![0x41u8; (1usize << 16) - 1];
    assert_eq!(too_long.len(), u16::MAX as usize);

    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    // Client Blind: input or info.
    assert_eq!(
        client
            .blind(&too_long, b"info", &mut rand_core::OsRng)
            .unwrap_err(),
        Error::InputTooLong,
        "Blind: oversized input not rejected"
    );
    assert_eq!(
        client
            .blind(b"input", &too_long, &mut rand_core::OsRng)
            .unwrap_err(),
        Error::InputTooLong,
        "Blind: oversized info not rejected"
    );

    // Build a legitimate batch so the rest of the params type-check.
    let (state, blinded) = client.blind(b"x", b"info", &mut OsRng).unwrap();
    let (evaluated, proof) = server
        .blind_evaluate(&mut OsRng, &blinded, b"info")
        .unwrap();

    // Client Finalize: input or info.
    assert_eq!(
        client
            .finalize(&too_long, &state, &evaluated, &blinded, &proof, b"info")
            .unwrap_err(),
        Error::InputTooLong,
        "Finalize: oversized input not rejected"
    );
    assert_eq!(
        client
            .finalize(b"x", &state, &evaluated, &blinded, &proof, &too_long)
            .unwrap_err(),
        Error::InputTooLong,
        "Finalize: oversized info not rejected"
    );

    // Client finalize_batch: any input element, or info.
    let states = vec![state.clone()];
    let evals = vec![evaluated.clone()];
    let blindeds = vec![blinded.clone()];
    assert_eq!(
        client
            .finalize_batch(
                &[too_long.as_slice()],
                &states,
                &evals,
                &blindeds,
                &proof,
                b"info"
            )
            .unwrap_err(),
        Error::InputTooLong,
        "finalize_batch: oversized input element not rejected"
    );
    assert_eq!(
        client
            .finalize_batch(
                &[b"x".as_ref()],
                &states,
                &evals,
                &blindeds,
                &proof,
                &too_long
            )
            .unwrap_err(),
        Error::InputTooLong,
        "finalize_batch: oversized info not rejected"
    );

    // Server blind_evaluate: oversized info.
    assert_eq!(
        server
            .blind_evaluate(&mut OsRng, &blinded, &too_long)
            .unwrap_err(),
        Error::InputTooLong,
        "blind_evaluate: oversized info not rejected"
    );
    // Server blind_evaluate_batch: oversized info.
    assert_eq!(
        server
            .blind_evaluate_batch(&mut OsRng, std::slice::from_ref(&blinded), &too_long)
            .unwrap_err(),
        Error::InputTooLong,
        "blind_evaluate_batch: oversized info not rejected"
    );

    // Server evaluate: oversized input or info.
    assert_eq!(
        server.evaluate(&too_long, b"info").unwrap_err(),
        Error::InputTooLong,
        "evaluate: oversized input not rejected"
    );
    assert_eq!(
        server.evaluate(b"x", &too_long).unwrap_err(),
        Error::InputTooLong,
        "evaluate: oversized info not rejected"
    );

    // DeriveKeyPair: oversized info.
    let seed = [0u8; 32];
    assert_eq!(
        derive_key_pair(&seed, &too_long).unwrap_err(),
        Error::InputTooLong,
        "derive_key_pair: oversized info not rejected"
    );
}

// ── finalize_batch tweakedKey consistency ────────────────────────────────────

/// `finalize_batch` must reject `PoprfBlindState` slices whose `tweakedKey`s
/// disagree. Such a batch can only arise from a buggy caller mixing states
/// produced for different `info` values into one batch; if accepted it would
/// pass DLEQ verification against `states[0]`'s tweakedKey but produce
/// silently incorrect outputs for the divergent entries.
#[test]
fn finalize_batch_rejects_mismatched_tweaked_key() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    let info_a = b"info-a";
    let info_b = b"info-b";

    // Produce a valid batch of size 1 under info_a so the DLEQ proof matches
    // states[0]'s tweakedKey.
    let (state_a, blinded_a) = client.blind(b"alpha", info_a, &mut OsRng).unwrap();
    let (evaluated_a, proof_a) = server
        .blind_evaluate(&mut OsRng, &blinded_a, info_a)
        .unwrap();

    // Build a divergent state under info_b. The blinded/evaluated pair is
    // irrelevant to the consistency check — we want to hit InconsistentState
    // before any crypto runs.
    let (state_b, blinded_b) = client.blind(b"beta", info_b, &mut OsRng).unwrap();
    let (evaluated_b, _) = server
        .blind_evaluate(&mut OsRng, &blinded_b, info_b)
        .unwrap();

    let err = client
        .finalize_batch(
            &[b"alpha".as_ref(), b"beta".as_ref()],
            &[state_a, state_b],
            &[evaluated_a, evaluated_b],
            &[blinded_a, blinded_b],
            &proof_a,
            info_a,
        )
        .unwrap_err();
    assert_eq!(
        err,
        Error::InconsistentState,
        "mismatched tweakedKey not detected"
    );
}

/// Maximum permitted size (`2^16 - 2`) must be accepted on all entry points.
#[test]
fn accepts_maximum_input_and_info_lengths() {
    // 2^16 - 2: the largest size strictly smaller than 2^16 - 1, hence
    // permitted per RFC 9497 §5.1.
    let max_ok = vec![0x42u8; (1usize << 16) - 2];

    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    let (state, blinded) = client.blind(&max_ok, &max_ok, &mut OsRng).unwrap();
    let (evaluated, proof) = server
        .blind_evaluate(&mut OsRng, &blinded, &max_ok)
        .unwrap();
    let out = client
        .finalize(&max_ok, &state, &evaluated, &blinded, &proof, &max_ok)
        .unwrap();
    let direct = server.evaluate(&max_ok, &max_ok).unwrap();
    assert_eq!(out, direct, "max-length input/info diverges");
}

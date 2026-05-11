//! End-to-end round-trip tests with random keys and blinding scalars.

use rand_core::OsRng;

use poprf_ristretto::{
    BlindedElement, Error, EvaluatedElement, PoprfBlindState, PoprfClient, PoprfOutput,
    PoprfServer, Proof, PublicKey, SecretKey,
};

#[test]
fn poprf_random_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    let input = b"poprf-input";
    let info = b"public-info";

    let (state, blinded) = client.blind(input, info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();
    let out = client
        .finalize(input, &state, &evaluated, &blinded, &proof, info)
        .expect("proof verifies");

    assert_eq!(out, server.evaluate(input, info).unwrap());
}

#[test]
fn poprf_batch_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    let info = b"batch-info";
    let inputs_raw: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];

    let mut states = Vec::new();
    let mut blindeds = Vec::new();
    for &inp in inputs_raw {
        let (s, b) = client.blind(inp, info, &mut OsRng).unwrap();
        states.push(s);
        blindeds.push(b);
    }

    let (evals, proof) = server
        .blind_evaluate_batch(&mut OsRng, &blindeds, info)
        .unwrap();

    let outputs = client
        .finalize_batch(inputs_raw, &states, &evals, &blindeds, &proof, info)
        .unwrap();

    for (output, &inp) in outputs.iter().zip(inputs_raw.iter()) {
        assert_eq!(*output, server.evaluate(inp, info).unwrap());
    }
}

#[test]
fn poprf_different_info_yields_different_output() {
    let server = PoprfServer::generate(&mut OsRng);
    let a = server.evaluate(b"x", b"info1").unwrap();
    let b = server.evaluate(b"x", b"info2").unwrap();
    assert_ne!(a, b);
}

#[test]
fn poprf_proof_rejects_wrong_pk() {
    let server = PoprfServer::generate(&mut OsRng);
    let other = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(other.public_key());

    let info = b"info";
    let (state, blinded) = client.blind(b"input", info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();
    let res = client.finalize(b"input", &state, &evaluated, &blinded, &proof, info);
    assert!(matches!(res, Err(Error::Verify)));
}

// ── wire-format round-trips ──────────────────────────────────────────────────

#[test]
fn secret_key_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let bytes = server.secret_key().to_bytes();
    let parsed = SecretKey::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_bytes(), bytes);
    assert_eq!(parsed.public_key(), server.public_key());
}

#[test]
fn public_key_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let pk = server.public_key();
    let bytes = pk.to_bytes();
    let parsed = PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, pk);
}

#[test]
fn blinded_element_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let (_, blinded) = client.blind(b"x", b"info", &mut OsRng).unwrap();
    let bytes = blinded.to_bytes();
    let parsed = BlindedElement::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_bytes(), bytes);
}

#[test]
fn evaluated_element_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let (_, blinded) = client.blind(b"x", b"info", &mut OsRng).unwrap();
    let (eval, _) = server
        .blind_evaluate(&mut OsRng, &blinded, b"info")
        .unwrap();
    let bytes = eval.to_bytes();
    let parsed = EvaluatedElement::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_bytes(), bytes);
}

#[test]
fn proof_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let (_, blinded) = client.blind(b"x", b"info", &mut OsRng).unwrap();
    let (_, proof) = server
        .blind_evaluate(&mut OsRng, &blinded, b"info")
        .unwrap();
    let bytes = proof.to_bytes();
    let parsed = Proof::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_bytes(), bytes);
}

#[test]
fn blind_state_roundtrip_and_finalize() {
    // The defining test: round-trip the blind state through bytes and prove
    // the client can still finalize a server response correctly.
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"info";
    let input = b"persisted-input";

    let (state, blinded) = client.blind(input, info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();

    let bytes = state.to_bytes();
    assert_eq!(bytes.len(), PoprfBlindState::LEN);
    let restored = PoprfBlindState::from_bytes(&bytes).unwrap();

    let out_a = client
        .finalize(input, &state, &evaluated, &blinded, &proof, info)
        .unwrap();
    let out_b = client
        .finalize(input, &restored, &evaluated, &blinded, &proof, info)
        .unwrap();
    assert_eq!(out_a, out_b);
    assert_eq!(out_a, server.evaluate(input, info).unwrap());
}

#[test]
fn poprf_output_constant_time_eq() {
    use subtle::ConstantTimeEq;
    let server = PoprfServer::generate(&mut OsRng);
    let a = server.evaluate(b"x", b"info").unwrap();
    let b = server.evaluate(b"x", b"info").unwrap();
    let c = server.evaluate(b"y", b"info").unwrap();

    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn poprf_output_from_bytes_roundtrip() {
    let server = PoprfServer::generate(&mut OsRng);
    let out = server.evaluate(b"x", b"info").unwrap();
    let bytes = *out.as_bytes();
    let parsed = PoprfOutput::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, out);
}

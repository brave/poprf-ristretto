//! Round-trip tests for the optional `serde` feature.
//!
//! Binary formats (postcard) use raw bytes; human-readable formats (JSON) use
//! lowercase hex strings.

#![cfg(feature = "serde")]

use rand_core::OsRng;

use poprf_ristretto::{
    BlindedElement, EvaluatedElement, PoprfBlindState, PoprfClient, PoprfOutput, PoprfServer,
    Proof, PublicKey, SecretKey,
};

fn fresh() -> (
    PoprfServer,
    PoprfClient,
    PoprfBlindState,
    BlindedElement,
    EvaluatedElement,
    Proof,
    PoprfOutput,
) {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());
    let info = b"info";
    let input = b"input";
    let (state, blinded) = client.blind(input, info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();
    let out = client
        .finalize(input, &state, &evaluated, &blinded, &proof, info)
        .unwrap();
    (server, client, state, blinded, evaluated, proof, out)
}

#[test]
fn postcard_roundtrip_all_wire_types() {
    let (server, _client, state, blinded, evaluated, proof, output) = fresh();
    let pk = server.public_key();
    let sk = server.secret_key().clone();

    macro_rules! rt {
        ($v:expr, $t:ty) => {{
            let bytes = postcard::to_allocvec(&$v).expect("serialize");
            let parsed: $t = postcard::from_bytes(&bytes).expect("deserialize");
            assert_eq!(parsed.to_bytes(), $v.to_bytes(), stringify!($t));
        }};
    }

    rt!(pk, PublicKey);
    rt!(sk, SecretKey);
    rt!(blinded, BlindedElement);
    rt!(evaluated, EvaluatedElement);
    rt!(proof, Proof);
    rt!(state, PoprfBlindState);

    // PoprfOutput uses as_bytes
    let out_bytes = postcard::to_allocvec(&output).unwrap();
    let parsed: PoprfOutput = postcard::from_bytes(&out_bytes).unwrap();
    assert_eq!(parsed, output);
}

#[test]
fn json_roundtrip_all_wire_types() {
    let (server, _client, state, blinded, evaluated, proof, output) = fresh();
    let pk = server.public_key();
    let sk = server.secret_key().clone();

    macro_rules! rt_json {
        ($v:expr, $t:ty) => {{
            let s = serde_json::to_string(&$v).expect("ser");
            // Must be a quoted hex string.
            assert!(s.starts_with('"') && s.ends_with('"'));
            assert!(s.len() >= 2 + 2 * <$t>::LEN);
            let parsed: $t = serde_json::from_str(&s).expect("de");
            assert_eq!(parsed.to_bytes(), $v.to_bytes(), stringify!($t));
        }};
    }

    rt_json!(pk, PublicKey);
    rt_json!(sk, SecretKey);
    rt_json!(blinded, BlindedElement);
    rt_json!(evaluated, EvaluatedElement);
    rt_json!(proof, Proof);
    rt_json!(state, PoprfBlindState);

    let s = serde_json::to_string(&output).unwrap();
    let parsed: PoprfOutput = serde_json::from_str(&s).unwrap();
    assert_eq!(parsed, output);
}

#[test]
fn json_rejects_non_canonical_encoding() {
    // Identity element encoded as 64-char hex zero string.
    let zero_hex = "\"0000000000000000000000000000000000000000000000000000000000000000\"";
    let result: Result<BlindedElement, _> = serde_json::from_str(zero_hex);
    assert!(
        result.is_err(),
        "BlindedElement deserialized identity from JSON"
    );
}

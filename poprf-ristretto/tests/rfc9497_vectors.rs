//! Integration tests against RFC 9497 Appendix A test vectors
//! for the POPRF/ristretto255-SHA512 ciphersuite.
//!
//! Vector source: https://www.rfc-editor.org/rfc/rfc9497 Appendix A.

use serde::Deserialize;

use poprf_ristretto::{PoprfClient, PoprfServer, derive_key_pair};

#[derive(Debug, Deserialize)]
struct VectorFile {
    suite: String,
    modes: ModeMap,
}

#[derive(Debug, Deserialize)]
struct ModeMap {
    #[serde(rename = "POPRF")]
    poprf: Option<ModeData>,
}

#[derive(Debug, Deserialize)]
struct ModeData {
    #[serde(rename = "Seed")]
    seed: String,
    #[serde(rename = "KeyInfo")]
    key_info: String,
    #[serde(rename = "skSm")]
    sk_sm: String,
    #[serde(rename = "pkSm")]
    pk_sm: Option<String>,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    #[serde(rename = "BatchSize")]
    batch_size: usize,
    #[serde(rename = "Input")]
    input: Vec<String>,
    #[serde(rename = "Info")]
    info: Option<String>,
    #[serde(rename = "Blind")]
    blind: Vec<String>,
    #[serde(rename = "BlindedElement")]
    blinded_element: Vec<String>,
    #[serde(rename = "EvaluationElement")]
    evaluation_element: Vec<String>,
    #[serde(rename = "Output")]
    output: Vec<String>,
    #[serde(rename = "Proof")]
    proof: Option<String>,
    #[serde(rename = "ProofRandomScalar")]
    proof_random_scalar: Option<String>,
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().expect("32 bytes")
}

fn load_vectors() -> VectorFile {
    let text = std::fs::read_to_string("tests/vectors/ristretto255-SHA512.json")
        .expect("read vectors file");
    serde_json::from_str(&text).expect("parse vectors json")
}

#[test]
fn poprf_ristretto255_sha512() {
    let f = load_vectors();
    assert_eq!(
        f.suite, "ristretto255-SHA512",
        "unexpected suite in vectors"
    );
    let m = f.modes.poprf.as_ref().expect("POPRF block present");

    let seed: [u8; 32] = h32(&m.seed);
    let key_info = h(&m.key_info);

    let (sk, pk) = derive_key_pair(&seed, &key_info).expect("DeriveKeyPair");

    assert_eq!(sk.to_bytes().to_vec(), h(&m.sk_sm), "skSm mismatch");
    assert_eq!(
        pk.to_bytes().to_vec(),
        h(m.pk_sm.as_deref().unwrap()),
        "pkSm mismatch"
    );

    let server = PoprfServer::new(sk);
    let client = PoprfClient::new(pk);

    for (vi, v) in m.vectors.iter().enumerate() {
        let info = h(v.info.as_deref().unwrap());
        let proof_r_bytes = h32(v.proof_random_scalar.as_deref().unwrap());

        let mut states = Vec::new();
        let mut blindeds = Vec::new();

        for i in 0..v.batch_size {
            let input = h(&v.input[i]);
            let blind_bytes = h32(&v.blind[i]);

            let (state, blinded) = client
                .blind_with_scalar(&input, &info, &blind_bytes)
                .expect("Blind");

            assert_eq!(
                blinded.to_bytes().to_vec(),
                h(&v.blinded_element[i]),
                "v{vi}.{i} BlindedElement"
            );
            states.push(state);
            blindeds.push(blinded);
        }

        let (evals, proof) = server
            .blind_evaluate_batch_with_proof_scalar(&blindeds, &info, &proof_r_bytes)
            .expect("BlindEvaluate");

        for (i, (eval, expected)) in evals.iter().zip(v.evaluation_element.iter()).enumerate() {
            assert_eq!(
                eval.to_bytes().to_vec(),
                h(expected),
                "v{vi}.{i} EvaluationElement"
            );
        }
        assert_eq!(
            proof.to_bytes().to_vec(),
            h(v.proof.as_deref().unwrap()),
            "v{vi} Proof"
        );

        let inputs_owned: Vec<Vec<u8>> = v.input[..v.batch_size].iter().map(|x| h(x)).collect();
        let inputs_ref: Vec<&[u8]> = inputs_owned.iter().map(|x| x.as_slice()).collect();

        let outputs = client
            .finalize_batch(&inputs_ref, &states, &evals, &blindeds, &proof, &info)
            .expect("Finalize");

        for (i, (out, expected)) in outputs.iter().zip(v.output.iter()).enumerate() {
            assert_eq!(out.as_bytes().to_vec(), h(expected), "v{vi}.{i} Output");
        }

        // Offline Evaluate must agree.
        for (i, (inp, expected)) in inputs_owned.iter().zip(v.output.iter()).enumerate() {
            let direct = server.evaluate(inp, &info).expect("Evaluate");
            assert_eq!(
                direct.as_bytes().to_vec(),
                h(expected),
                "v{vi}.{i} Evaluate"
            );
        }
    }
}

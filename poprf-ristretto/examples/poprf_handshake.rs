//! POPRF (ristretto255-SHA512) handshake demo with public input.
//!
//! Protocol: https://www.rfc-editor.org/rfc/rfc9497 §3.3.3
//!
//! Run with: `cargo run --example poprf_handshake`

use poprf_ristretto::{PoprfClient, PoprfServer};
use rand_core::OsRng;

fn main() {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    let input = b"private input";
    let info = b"public info";

    let (state, blinded) = client.blind(input, info, &mut OsRng).unwrap();
    let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, info).unwrap();

    let out = client
        .finalize(input, &state, &evaluated, &blinded, &proof, info)
        .expect("proof verifies");

    println!("output: {}", hex(out.as_bytes()));

    // The same output is produced by direct server-side evaluation.
    let direct = server.evaluate(input, info).unwrap();
    assert_eq!(out, direct);
    println!("matches offline Evaluate: ok");

    // Outputs differ when info changes.
    let other = server.evaluate(input, b"different info").unwrap();
    assert_ne!(out, other);
    println!("different info produces different output: ok");
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, byte| {
        use core::fmt::Write;
        write!(&mut s, "{byte:02x}").unwrap();
        s
    })
}

//! Criterion benchmarks for the POPRF/ristretto255-SHA512 protocol.
//!
//! Protocol: https://www.rfc-editor.org/rfc/rfc9497 §3.3.3
//!
//! Run: `cargo bench --bench poprf`

#![allow(clippy::clone_on_copy)]

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand_core::OsRng;

use poprf_ristretto::{BlindedElement, PoprfBlindState, PoprfClient, PoprfServer};

const INPUT: &[u8] = b"poprf-bench-input---32-bytes----";
const INFO: &[u8] = b"benchmark-info";
const BATCH_SIZES: &[usize] = &[1, 32, 64];

fn make_blinded(client: &PoprfClient, n: usize) -> (Vec<PoprfBlindState>, Vec<BlindedElement>) {
    let mut states = Vec::with_capacity(n);
    let mut blinded = Vec::with_capacity(n);
    for _ in 0..n {
        let (s, b) = client.blind(INPUT, INFO, &mut OsRng).unwrap();
        states.push(s);
        blinded.push(b);
    }
    (states, blinded)
}

fn bench_poprf(c: &mut Criterion) {
    let server = PoprfServer::generate(&mut OsRng);
    let client = PoprfClient::new(server.public_key());

    let mut g = c.benchmark_group("poprf/ristretto255-SHA512");

    g.bench_function("blind", |b| {
        b.iter_batched(
            || (),
            |_| client.blind(INPUT, INFO, &mut OsRng).unwrap(),
            BatchSize::SmallInput,
        );
    });

    g.bench_function("blind_evaluate", |b| {
        b.iter_batched(
            || client.blind(INPUT, INFO, &mut OsRng).unwrap().1,
            |bl| server.blind_evaluate(&mut OsRng, &bl, INFO).unwrap(),
            BatchSize::SmallInput,
        );
    });

    g.bench_function("finalize", |b| {
        b.iter_batched(
            || {
                let (state, blinded) = client.blind(INPUT, INFO, &mut OsRng).unwrap();
                let (evaluated, proof) = server.blind_evaluate(&mut OsRng, &blinded, INFO).unwrap();
                (state, blinded, evaluated, proof)
            },
            |(state, blinded, evaluated, proof)| {
                client
                    .finalize(INPUT, &state, &evaluated, &blinded, &proof, INFO)
                    .unwrap()
            },
            BatchSize::SmallInput,
        );
    });

    g.bench_function("evaluate", |b| {
        b.iter(|| server.evaluate(INPUT, INFO).unwrap());
    });

    for &n in BATCH_SIZES {
        let sample_size = match n {
            0..=8 => 100,
            9..=16 => 40,
            _ => 20,
        };
        g.throughput(Throughput::Elements(n as u64));
        g.sample_size(sample_size);

        g.bench_with_input(BenchmarkId::new("blind_evaluate_batch", n), &n, |b, &n| {
            b.iter_batched(
                || make_blinded(&client, n).1,
                |blinded| {
                    server
                        .blind_evaluate_batch(&mut OsRng, &blinded, INFO)
                        .unwrap()
                },
                BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("finalize_batch", n), &n, |b, &n| {
            b.iter_batched(
                || {
                    let (states, blinded) = make_blinded(&client, n);
                    let (evals, proof) = server
                        .blind_evaluate_batch(&mut OsRng, &blinded, INFO)
                        .unwrap();
                    let inputs: Vec<&[u8]> = (0..n).map(|_| INPUT).collect();
                    (inputs, states, blinded, evals, proof)
                },
                |(inputs, states, blinded, evals, proof)| {
                    client
                        .finalize_batch(&inputs, &states, &evals, &blinded, &proof, INFO)
                        .unwrap()
                },
                BatchSize::SmallInput,
            );
        });

        g.bench_with_input(BenchmarkId::new("full_handshake_batch", n), &n, |b, &n| {
            b.iter_batched(
                || (),
                |_| {
                    let (states, blinded) = make_blinded(&client, n);
                    let (evals, proof) = server
                        .blind_evaluate_batch(&mut OsRng, &blinded, INFO)
                        .unwrap();
                    let inputs: Vec<&[u8]> = (0..n).map(|_| INPUT).collect();
                    client
                        .finalize_batch(&inputs, &states, &evals, &blinded, &proof, INFO)
                        .unwrap()
                },
                BatchSize::LargeInput,
            );
        });
    }

    g.finish();
}

criterion_group!(benches, bench_poprf);
criterion_main!(benches);

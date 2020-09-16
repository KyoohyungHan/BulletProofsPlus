#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;
use criterion::Criterion;

use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use bulletproofsplus::PublicKey;
use bulletproofsplus::range::{RangeProof, RangeProver, RangeVerifier};

static AGGREGATION_SIZES: [usize; 1] = [256];

fn bsplus_verify_aggregated_rangeproof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Aggregated {}-bit rangeproof verification", n);

    c.bench_function_over_inputs(
        &label,
        move |b, &&m| {
            let pk = PublicKey::new(n * m);
            let mut prover = RangeProver::new();
            for _i in 0..m {
                prover.commit(&pk, 31u64, Scalar::random(&mut OsRng));
            }
            let mut prover_transcript = Transcript::new(b"RangeProof Test");
            let proof: RangeProof = RangeProof::prove(
                &mut prover_transcript,
                &pk,
                n,
                &prover,
            );
            let mut verifier = RangeVerifier::new();
            verifier.allocate(&prover.commitment_vec);
            b.iter(|| {
                // Each proof creation requires a clean transcript.
                let mut transcript = Transcript::new(b"RangeProof Test");
                proof.verify(&mut transcript, &pk, n, &verifier)
            });
        },
        &AGGREGATION_SIZES,
    );
}

fn bsplus_verify_aggregated_rangeproof_n_32(c: &mut Criterion) {
    bsplus_verify_aggregated_rangeproof_helper(32, c);
}

fn bsplus_verify_aggregated_rangeproof_n_64(c: &mut Criterion) {
    bsplus_verify_aggregated_rangeproof_helper(64, c);
}

criterion_group! {
    name = verify_rp;
    config = Criterion::default().sample_size(50);
    targets =
    bsplus_verify_aggregated_rangeproof_n_64,
}

criterion_main!(verify_rp);
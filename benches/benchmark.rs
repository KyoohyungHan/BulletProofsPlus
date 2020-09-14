use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofsplus::PublicKey;
use bulletproofsplus::range::{RangeProof, RangeProver, RangeVerifier};
use criterion::Bencher;

fn range_proof_verify(b: &mut Bencher, n: usize, m: usize) {
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
    let mut verifier_transcript = Transcript::new(b"RangeProof Test");
    let mut verifier = RangeVerifier::new();
    verifier.allocate(&prover.commitment_vec);
    b.iter(|| proof.verify(
        &mut verifier_transcript,
        &pk,
        n,
        &verifier,
    ));
}

pub fn range_proof_verify_benchmark(c: &mut Criterion) {
    c.bench_function("range_proof_verify 64x2", |b| range_proof_verify(b, 64, 2));
    c.bench_function("range_proof_verify 64x4", |b| range_proof_verify(b, 64, 4));
    c.bench_function("range_proof_verify 64x8", |b| range_proof_verify(b, 64, 8));
    c.bench_function("range_proof_verify 64x16", |b| range_proof_verify(b, 64, 16));
}

criterion_group!(benches, range_proof_verify_benchmark);
criterion_main!(benches);
use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofsplus::PublicKey;
use bulletproofsplus::range::{RangeProof, RangeProver, RangeVerifier};
use std::time::Instant;

fn main() {
    let n = 64;
    let m = 256;
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
    let commitment_vec = prover.commitment_vec;
    let start = Instant::now();
    for _i in 0..10 {
        let mut transcript = Transcript::new(b"RangeProof Test");
        let result = proof.verify(
            &mut transcript,
            &pk,
            n,
            &commitment_vec,
        );
        assert_eq!(result, Ok(()));
    }
    println!("10xTime : {:?}", start.elapsed());
    println!("done");
}
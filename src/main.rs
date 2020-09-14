use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofsplus::PublicKey;
use bulletproofsplus::range::{RangeProof, RangeProver, RangeVerifier};
use std::time::{Duration, Instant};

fn main() {
    let mut duration = Duration::new(0, 0);
    let n = 32;
    let m = 16;
    let pk = PublicKey::new(n * m);
    let mut prover = RangeProver::new();
    for _i in 0..m {
        prover.commit(&pk, 31u64, Scalar::random(&mut OsRng));
    }   
    for _t in 0..10 {
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
        let start = Instant::now();
        let result = proof.verify(
            &mut verifier_transcript,
            &pk,
            n,
            &verifier,
        );
        duration = duration + start.elapsed();
        assert_eq!(result, Ok(()));
    }
    println!("Time elapsed in verify is: {:?}", duration / 10);
}
use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use bulletproofsplus::PublicKey;
use bulletproofsplus::range::{RangeProof, RangeProver, RangeVerifier};

fn main() {
    let n = 32;
    let m = 16;
    let pk = PublicKey::new(n * m);
    let mut prover = RangeProver::new();
    println!("Commit Values");
    for _i in 0..m {
        prover.commit(&pk, 31u64, Scalar::random(&mut OsRng));
    }
    let mut prover_transcript = Transcript::new(b"RangeProof Test");
    println!("Prove All Values are in [0, 2^32)");
    let proof: RangeProof = RangeProof::prove(
        &mut prover_transcript,
        &pk,
        n,
        &prover,
    );
    let mut verifier_transcript = Transcript::new(b"RangeProof Test");
    let mut verifier = RangeVerifier::new();
    verifier.allocate(&prover.commitment_vec);
    println!("Verify Proof");
    let result = proof.verify(
        &mut verifier_transcript,
        &pk,
        n,
        &verifier,
    );
    assert_eq!(result, Ok(()));
    println!("done");
}
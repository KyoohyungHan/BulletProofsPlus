# BulletProofs+
A pure rust implementation of Bulletproofs+ Scheme

## Bulletproof+
This scheme is simpler with smaller proof size than the original bulletproof scheme. We used weighted inner product zero-knowledge argument instead of inner product argument.

### Compile
To run main.rs,
```rust
cargo +nightly run --release
```
To run basic tests,
```rust
cargo +nightly test --release
```

### Example - Range Proof
```rust
use rand_core::OsRng;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use improvedbulletproof::PublicKey;
use improvedbulletproof::range::{RangeProof, RangeProver, RangeVerifier};

fn main() {
    let n = 32;
    let m = 16;
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
    let result = proof.verify(
        &mut verifier_transcript,
        &pk,
        n,
        &verifier,
    );
    assert_eq!(result, Ok(()));
}
```

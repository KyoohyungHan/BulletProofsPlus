#![allow(non_snake_case)]

extern crate test;

use core::iter;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand_core::OsRng;

#[allow(unused_imports)]
use super::{ConstraintSystem, LinearCombination, R1CSProver, R1CSVerifier, Variable};
#[allow(unused_imports)]
use crate::errors::{ProofError, R1CSError};
use crate::publickey::PublicKey;
use crate::transcript::TranscriptProtocol;
use crate::util;
use crate::weighted_inner_product_proof::WeightedInnerProductProof;

#[derive(Clone, Debug)]
pub struct R1CSProof {
    pub A: CompressedRistretto,
    pub proof: WeightedInnerProductProof,
}

impl R1CSProof {
    pub fn prove(
        transcript: &mut Transcript,
        pk: &PublicKey,
        prover: &R1CSProver,
        commitment_vec: &[RistrettoPoint],
    ) -> Self {
        let n = prover.a_L.len();
        assert_eq!(prover.a_R.len(), n);
        assert_eq!(prover.a_O.len(), n);
        let m = prover.v_vec.len();
        assert_eq!(prover.gamma_vec.len(), m);
        // compute A
        let mut rng = OsRng;
        let alpha = Scalar::random(&mut rng);
        let A = RistrettoPoint::multiscalar_mul(
            prover.a_L.iter().cloned()
                .chain(prover.a_O.iter().cloned())
                .chain(prover.a_R.iter().cloned())
                .chain(vec![Scalar::zero(); n].iter().cloned())
                .chain(iter::once(alpha)),
            pk.G_vec.iter().cloned()
                .chain(pk.H_vec.iter().cloned())
                .chain(iter::once(pk.h)),
        );
        // get challenges
        transcript.append_point(b"A", &(A.compress()));
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let (T_WL, T_WR, T_WO, zQ_WV, zQ_C) = prover.flattened_constraints(&y, &z);
        // compute A_hat
        let twon = 2 * n;
        let power_of_y: Vec<Scalar> = util::exp_iter_type2(y).take(twon).collect();
        let (power_of_y1, _) = power_of_y.split_at(n);
        let y_inv = y.invert();
        let power_of_y_inv_n = util::scalar_exp_vartime(&y_inv, n as u64);
        let one = Scalar::one();
        let G1_exp = T_WR;
        let H1_exp = T_WL;
        let H2_exp: Vec<Scalar> = T_WO
            .iter()
            .map(|T_WO_i| power_of_y_inv_n * (T_WO_i - one))
            .collect();
        let g_exp = zQ_C + util::weighted_inner_product(&G1_exp, &H1_exp, &power_of_y1);
        let V_exp = zQ_WV;
        let A_hat = RistrettoPoint::multiscalar_mul(
            iter::once(Scalar::one())
                .chain(G1_exp.iter().cloned())
                .chain(vec![Scalar::zero(); n].iter().cloned())
                .chain(H1_exp.iter().cloned())
                .chain(H2_exp.iter().cloned())
                .chain(iter::once(g_exp))
                .chain(V_exp.iter().cloned()),
            iter::once(A)
                .chain(pk.G_vec.iter().cloned())
                .chain(pk.H_vec.iter().cloned())
                .chain(iter::once(pk.g))
                .chain(commitment_vec.iter().cloned()),
        );
        // compute a_vec, b_vec, alpha_hat
        let mut a_vec: Vec<Scalar> = Vec::with_capacity(2 * n);
        let mut b_vec: Vec<Scalar> = Vec::with_capacity(2 * n);
        for i in 0..n {
            a_vec.push(prover.a_L[i] + G1_exp[i]);
            b_vec.push(prover.a_R[i] + H1_exp[i]);
        }
        for i in 0..n {
            a_vec.push(prover.a_O[i]);
            b_vec.push(H2_exp[i]);
        }
        let alpha_hat = alpha + util::inner_product(&V_exp, &prover.gamma_vec);
        // generate weighted inner product proof
        let proof = WeightedInnerProductProof::prove(
            transcript,
            pk,
            &a_vec,
            &b_vec,
            &power_of_y,
            alpha_hat,
            A_hat,
        );
        R1CSProof {
            A: A.compress(),
            proof: proof,
        }
    }
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        pk: &PublicKey,
        verifier: &R1CSVerifier,
        commitment_vec: &[RistrettoPoint],
    ) -> Result<(), ProofError> {
        let n = verifier.num_vars;
        transcript.append_point(b"A", &self.A);
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let As = match self.A.decompress() {
            Some(point) => point,
            None => panic!("fail to decompress"),
        };
        let (T_WL, T_WR, T_WO, zQ_WV, zQ_C) = verifier.flattened_constraints(&y, &z);
        // compute exponents of A_hat
        let twon = 2 * n;
        let power_of_y: Vec<Scalar> = util::exp_iter_type2(y).take(twon).collect();
        let (power_of_y1, _) = power_of_y.split_at(n);
        let y_inv = y.invert();
        let power_of_y_inv_n = util::scalar_exp_vartime(&y_inv, n as u64);
        let one = Scalar::one();
        let G1_exp = T_WR;
        let zero_vec = vec![Scalar::zero(); n];
        let H1_exp = T_WL;
        let H2_exp: Vec<Scalar> = T_WO
            .iter()
            .map(|T_WO_i| power_of_y_inv_n * (T_WO_i - one))
            .collect();
        let G_exp = [&G1_exp[..], &zero_vec[..]].concat();
        let H_exp = [&H1_exp[..], &H2_exp[..]].concat();
        let g_exp = zQ_C + util::weighted_inner_product(&G1_exp, &H1_exp, &power_of_y1);
        let V_exp = zQ_WV;
        // verify weighted inner product proof
        self.proof.verify_with_exponents_of_a_hat(
            transcript,
            pk,
            &power_of_y,
            &G_exp,
            &H_exp,
            &g_exp,
            &V_exp,
            As,
            &commitment_vec,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(dead_code)]
    fn gadget<CS: ConstraintSystem> (
        cs: &mut CS,
        x: &Vec<Variable>,
        y: &Vec<Variable>,
        z: &Vec<Scalar>,
        n: usize,
    ) {
        for i in 0..n {
            for j in 0..n {
                let (_, _, varxy) = cs.multiply(x[n * i].into(), y[j].into());
                let mut lc: LinearCombination = LinearCombination::from(varxy);
                for k in 1..n {
                    let (_, _, varxy) = cs.multiply(x[n * i + k].into(), y[n * k + j].into());
                    lc = lc + varxy;
                }
                let z_lc: LinearCombination = vec![(Variable::One(), z[n * i + j].into())]
                    .iter().collect();
                lc = lc - z_lc;
                cs.constrain(lc);
            }
        }
    }
    #[allow(dead_code)]
    fn test_matmul_r1cs(n: usize) {
        let pk = PublicKey::new(2 * n * n * n);
        //
        let mut prover: R1CSProver = ConstraintSystem::new();
        let mut verifier: R1CSVerifier = ConstraintSystem::new();
        //
        let mut matrix1 = Vec::with_capacity(n * n);
        let mut matrix2 = Vec::with_capacity(n * n);
        for _i in 0..(n*n) {
            matrix1.push(Scalar::random(&mut OsRng));
            matrix2.push(Scalar::random(&mut OsRng));
        }
        let mut r = vec![Scalar::zero(); n*n];
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    r[n * i + j] += matrix1[n * i + k] * matrix2[n * k + j];
                }
            }
        }
        //
        let mut var1 = Vec::with_capacity(n * n);
        let mut var2 = Vec::with_capacity(n * n);
        let mut commitment_vec = Vec::with_capacity(2 * n * n);
        for i in 0..n {
            for j in 0..n {
                let (comm, var) = prover.commit(&pk, matrix1[n * i + j].into(), Scalar::random(&mut OsRng));
                var1.push(var);
                commitment_vec.push(comm);
            }
        }
        for i in 0..n {
            for j in 0..n {
                let (comm, var) = prover.commit(&pk, matrix2[n * i + j].into(), Scalar::random(&mut OsRng));
                var2.push(var);
                commitment_vec.push(comm);
            }
        }
        gadget(&mut prover, &var1, &var2, &r, n);
        //
        let mut var1 = Vec::with_capacity(n * n);
        let mut var2 = Vec::with_capacity(n * n);
        for i in 0..(n*n) {
            let var = verifier.commit(commitment_vec[i]);
            var1.push(var);
        }
        for i in 0..(n*n) {
            let var = verifier.commit(commitment_vec[(n*n)+i]);
            var2.push(var);
        }
        gadget(&mut verifier, &var1, &var2, &r, n);
        //
        let mut transcript = Transcript::new(b"R1CS Test");
        let proof = R1CSProof::prove(
            &mut transcript,
            &pk,
            &prover,
            &commitment_vec);
        let mut transcript = Transcript::new(b"R1CS Test");
        let result = proof.verify(
            &mut transcript,
            &pk,
            &verifier,
            &commitment_vec);
        assert_eq!(result, Ok(()));
    }
    #[test]
    fn test_matmul_r1cs_all() {
        test_matmul_r1cs(2 as usize);
        test_matmul_r1cs(4 as usize);
    }
    
    use test::Bencher;
    #[allow(dead_code)]
    fn bench_matmul_prove(b: &mut Bencher, n: usize) {
        let pk = PublicKey::new(2 * n * n * n);
        //
        let mut prover: R1CSProver = ConstraintSystem::new();
        //
        let mut matrix1 = Vec::with_capacity(n * n);
        let mut matrix2 = Vec::with_capacity(n * n);
        for _i in 0..(n*n) {
            matrix1.push(Scalar::random(&mut OsRng));
            matrix2.push(Scalar::random(&mut OsRng));
        }
        let mut r = vec![Scalar::zero(); n*n];
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    r[n * i + j] += matrix1[n * i + k] * matrix2[n * k + j];
                }
            }
        }
        //
        let mut var1 = Vec::with_capacity(n * n);
        let mut var2 = Vec::with_capacity(n * n);
        let mut commitment_vec = Vec::with_capacity(2 * n * n);
        for i in 0..n {
            for j in 0..n {
                let (comm, var) = prover.commit(&pk, matrix1[n * i + j].into(), Scalar::random(&mut OsRng));
                var1.push(var);
                commitment_vec.push(comm);
            }
        }
        for i in 0..n {
            for j in 0..n {
                let (comm, var) = prover.commit(&pk, matrix2[n * i + j].into(), Scalar::random(&mut OsRng));
                var2.push(var);
                commitment_vec.push(comm);
            }
        }
        gadget(&mut prover, &var1, &var2, &r, n);
        //
        let mut transcript = Transcript::new(b"R1CS Test");
        b.iter(|| R1CSProof::prove(
            &mut transcript,
            &pk,
            &prover,
            &commitment_vec));
    }
    #[allow(dead_code)]
    fn bench_matmul_verify(b: &mut Bencher, n: usize) {
        let pk = PublicKey::new(2 * n * n * n);
        //
        let mut prover: R1CSProver = ConstraintSystem::new();
        let mut verifier: R1CSVerifier = ConstraintSystem::new();
        //
        let mut matrix1 = Vec::with_capacity(n * n);
        let mut matrix2 = Vec::with_capacity(n * n);
        for _i in 0..(n*n) {
            matrix1.push(Scalar::random(&mut OsRng));
            matrix2.push(Scalar::random(&mut OsRng));
        }
        let mut r = vec![Scalar::zero(); n*n];
        for i in 0..n {
            for j in 0..n {
                for k in 0..n {
                    r[n * i + j] += matrix1[n * i + k] * matrix2[n * k + j];
                }
            }
        }
        //
        let mut var1 = Vec::with_capacity(n * n);
        let mut var2 = Vec::with_capacity(n * n);
        let mut commitment_vec = Vec::with_capacity(2 * n * n);
        for i in 0..n {
            for j in 0..n {
                let (comm, var) = prover.commit(&pk, matrix1[n * i + j].into(), Scalar::random(&mut OsRng));
                var1.push(var);
                commitment_vec.push(comm);
            }
        }
        for i in 0..n {
            for j in 0..n {
                let (comm, var) = prover.commit(&pk, matrix2[n * i + j].into(), Scalar::random(&mut OsRng));
                var2.push(var);
                commitment_vec.push(comm);
            }
        }
        gadget(&mut prover, &var1, &var2, &r, n);
        //
        let mut var1 = Vec::with_capacity(n * n);
        let mut var2 = Vec::with_capacity(n * n);
        for i in 0..(n*n) {
            let var = verifier.commit(commitment_vec[i]);
            var1.push(var);
        }
        for i in 0..(n*n) {
            let var = verifier.commit(commitment_vec[(n*n)+i]);
            var2.push(var);
        }
        gadget(&mut verifier, &var1, &var2, &r, n);
        //
        let mut transcript = Transcript::new(b"R1CS Test");
        let proof = R1CSProof::prove(
            &mut transcript,
            &pk,
            &prover,
            &commitment_vec);
        let mut transcript = Transcript::new(b"R1CS Test");
        b.iter(|| proof.verify(
            &mut transcript,
            &pk,
            &verifier,
            &commitment_vec));
    }
    #[bench]
    fn bench_matmul_prove_2x2(b: &mut Bencher) {
        bench_matmul_prove(b, 2 as usize);
    }
    #[bench]
    fn bench_matmul_verify_2x2(b: &mut Bencher) {
        bench_matmul_verify(b, 2 as usize);
    }
    #[bench]
    fn bench_matmul_prove_4x4(b: &mut Bencher) {
        bench_matmul_prove(b, 4 as usize);
    }
    #[bench]
    fn bench_matmul_verify_4x4(b: &mut Bencher) {
        bench_matmul_verify(b, 4 as usize);
    }
    #[bench]
    fn bench_matmul_prove_8x8(b: &mut Bencher) {
        bench_matmul_prove(b, 8 as usize);
    }
    #[bench]
    fn bench_matmul_verify_8x8(b: &mut Bencher) {
        bench_matmul_verify(b, 8 as usize);
    }
}
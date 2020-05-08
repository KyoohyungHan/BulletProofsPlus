#![allow(non_snake_case)]

extern crate alloc;
extern crate hex;
extern crate test;

use alloc::vec::Vec;
use core::iter;
use rand_core::OsRng;
use std::mem;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimeMultiscalarMul};
use merlin::Transcript;

use super::{RangeProver, RangeVerifier};
use crate::util;
use crate::errors::ProofError;
use crate::transcript::TranscriptProtocol;
use crate::publickey::PublicKey;
use crate::weighted_inner_product_proof::WeightedInnerProductProof;

#[derive(Clone, Debug)]
pub struct RangeProof {
    pub A: CompressedRistretto,
    pub proof: WeightedInnerProductProof,
}

impl RangeProof {
    pub fn prove(
        transcript: &mut Transcript,
        pk: &PublicKey,
        n: usize,
        prover: &RangeProver,
    ) -> Self {
        let m = prover.v_vec.len();
        if m == 1 {
            // single proof case
            Self::prove_single(
                transcript,
                pk,
                n,
                prover.v_vec[0],
                &prover.gamma_vec[0],
                &prover.commitment_vec[0])
        } else {
            // aggregate proof case
            Self::prove_multiple(
                transcript,
                pk,
                n,
                m,
                &prover.v_vec,
                &prover.gamma_vec,
                &prover.commitment_vec,
            )
        }
    }
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        pk: &PublicKey,
        n: usize,
        verifier: &RangeVerifier,
    ) -> Result<(), ProofError> {
        let m = verifier.commitment_vec.len();
        if m == 1 {
            self.verify_single(
                transcript,
                pk,
                n,
                &verifier.commitment_vec[0],
            )
        } else {
            self.verify_multiple(
                transcript,
                pk,
                n,
                m,
                &verifier.commitment_vec,
            )
        }
    }
    //
    fn prove_single(
        transcript: &mut Transcript,
        pk: &PublicKey,
        n: usize,
        v: u64,
        gamma: &Scalar,
        commitment: &RistrettoPoint,
    ) -> RangeProof {
        // check parameter
        assert_eq!(pk.G_vec.len(), n);
        assert_eq!(pk.H_vec.len(), n);
        // random number generator
        let mut csprng = OsRng;
        // random alpha
        let alpha = Scalar::random(&mut csprng);
        // compute A
        use subtle::{Choice, ConditionallySelectable};
        let mut v_bits: Vec<Choice> = Vec::with_capacity(n);
        let mut A = pk.h * alpha;
        let mut i = 0;
        for (G_i, H_i) in pk.G_vec.iter().zip(pk.H_vec.iter()) {
            v_bits.push(Choice::from(((v >> i) & 1) as u8));
            let mut point = -H_i;
            point.conditional_assign(G_i, v_bits[i]);
            A += point;
            i += 1;
        }
        // get challenges
        transcript.append_point(b"A", &(A.compress()));
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        // compute A_hat
        let one = Scalar::one();
        let two = Scalar::from(2u64);
        let power_of_two: Vec<Scalar> = util::exp_iter_type1(Scalar::from(2u64)).take(n).collect();
        let power_of_y: Vec<Scalar> = util::exp_iter_type2(y).take(n).collect();
        let power_of_y_rev = power_of_y
            .clone()
            .into_iter()
            .rev();
        let G_vec_sum: RistrettoPoint = pk.G_vec.iter().sum();
        let G_vec_sum_exp = -z;
        let H_exp: Vec<Scalar> = power_of_two
            .iter()
            .zip(power_of_y_rev)
            .map(|(power_of_two_i, power_of_y_rev_i)| power_of_two_i * power_of_y_rev_i + z)
            .collect();
        let V_exp = util::scalar_exp_vartime(&y, (n + 1) as u64);
        let mut g_exp: Scalar = power_of_y.iter().sum();
        g_exp *= z - z * z;
        g_exp -= (util::scalar_exp_vartime(&two, n as u64) - one) * V_exp * z;
        let A_hat = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(G_vec_sum_exp))
                .chain(H_exp.iter().cloned())
                .chain(iter::once(g_exp))
                .chain(iter::once(V_exp)),
            iter::once(A)
                .chain(iter::once(G_vec_sum))
                .chain(pk.H_vec.iter().cloned())
                .chain(iter::once(pk.g))
                .chain(iter::once(*commitment)),    
        );
        // compute a_vec, b_vec, alpha_hat
        let nz = -z;
        let one_minus_z = one - z;
        let a_vec: Vec<Scalar> = v_bits
            .iter()
            .map(|v_bits_i| Scalar::conditional_select(&nz, &one_minus_z, *v_bits_i))
            .collect();
        let b_vec: Vec<Scalar> = H_exp
            .iter()
            .zip(v_bits.iter())
            .map(|(H_exp_i, v_bits_i)| {
                Scalar::conditional_select(&(H_exp_i - one), H_exp_i, *v_bits_i)
            })
            .collect();
        let alpha_hat = alpha + gamma * V_exp;
        // generate weighted inner product proof
        let proof = WeightedInnerProductProof::prove(
            transcript,
            &pk,
            &a_vec,
            &b_vec,
            &power_of_y,
            alpha_hat,
            A_hat,
        );
        RangeProof {
            A: A.compress(),
            proof: proof,
        }
    }
    fn prove_multiple(
        transcript: &mut Transcript,
        pk: &PublicKey,
        n: usize,
        m: usize,
        v: &[u64],
        gamma_vec: &[Scalar],
        commitment_vec: &[RistrettoPoint],
    ) -> RangeProof {
        let mn = n * m;
        // check parameter
        assert_eq!(pk.G_vec.len(), mn);
        assert_eq!(pk.H_vec.len(), mn);
        // random number generator
        let mut csprng = OsRng;
        // random alpha
        let alpha = Scalar::random(&mut csprng);
        // compute A
        use subtle::{Choice, ConditionallySelectable};
        let mut v_bits: Vec<Choice> = Vec::with_capacity(mn);
        let mut A = pk.h * alpha;
        let mut i = 0;
        for (G_i, H_i) in pk.G_vec.iter().zip(pk.H_vec.iter()) {
            let index1 = i % n;
            let index2 = i / n;
            v_bits.push(Choice::from(((v[index2] >> index1) & 1) as u8));
            let mut point = -H_i;
            point.conditional_assign(G_i, v_bits[i]);
            A += point;
            i += 1;
        }
        transcript.append_point(b"A", &(A.compress()));
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        // compute d
        let power_of_two: Vec<Scalar> = util::exp_iter_type1(Scalar::from(2u64)).take(n).collect();
        let power_of_y: Vec<Scalar> = util::exp_iter_type2(y).take(mn).collect();
        let power_of_y_rev: Vec<Scalar> = power_of_y
            .clone()
            .into_iter()
            .rev()
            .collect::<Vec<Scalar>>();
        let z_sqr = z * z;
        let power_of_z: Vec<Scalar> = util::exp_iter_type2(z_sqr).take(m).collect();
        let d: Vec<Scalar> = power_of_z
            .iter()
            .flat_map(|exp_z| power_of_two.iter().map(move |exp_2| exp_2 * exp_z))
            .collect();
        // compute A_hat
        let G_vec_sum_exp = -z;
        let H_exp: Vec<Scalar> = d
            .iter()
            .zip(power_of_y_rev.iter())
            .map(|(d_i, power_of_y_rev_i)| d_i * power_of_y_rev_i + z)
            .collect();
        let power_of_y_mn_plus_1 = util::scalar_exp_vartime(&y, (mn + 1) as u64);
        let V_exp: Vec<Scalar> = power_of_z
            .iter()
            .map(|power_of_z_i| power_of_z_i * power_of_y_mn_plus_1)
            .collect();
        let mut g_exp: Scalar = power_of_y.iter().sum();
        g_exp *= z - z_sqr;
        let d_sum: Scalar = d.iter().sum();
        g_exp -= d_sum * power_of_y_mn_plus_1 * z;
        let G_vec_sum: RistrettoPoint = pk.G_vec.iter().sum();
        let A_hat = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(G_vec_sum_exp))
                .chain(H_exp.iter().cloned())
                .chain(iter::once(g_exp))
                .chain(V_exp.iter().cloned()),
            iter::once(A)
                .chain(iter::once(G_vec_sum))
                .chain(pk.G_vec.iter().cloned())
                .chain(iter::once(pk.g))
                .chain(commitment_vec.iter().cloned())
        );
        // compute a_vec, b_vec, alpha_hat
        let one = Scalar::one();
        let nz = -z;
        let one_minus_z = one - z;
        let a_vec: Vec<Scalar> = v_bits
            .iter()
            .map(|v_bits_i| Scalar::conditional_select(&nz, &one_minus_z, *v_bits_i))
            .collect();
        let b_vec: Vec<Scalar> = H_exp
            .iter()
            .zip(v_bits.iter())
            .map(|(H_exp_i, v_bits_i)| {
                Scalar::conditional_select(&(H_exp_i - one), H_exp_i, *v_bits_i)
            })
            .collect();
        let power_of_z_gamma_sum: Scalar = power_of_z
            .iter()
            .zip(gamma_vec.iter())
            .map(|(power_of_z_i, gamma_i)| power_of_z_i * gamma_i )
            .sum();
        let alpha_hat = alpha + power_of_z_gamma_sum * power_of_y_mn_plus_1;
        // generate weighted inner product proof
        let proof = WeightedInnerProductProof::prove(
            transcript,
            &pk,
            &a_vec,
            &b_vec,
            &power_of_y,
            alpha_hat,
            A_hat,
        );
        RangeProof {
            A: A.compress(),
            proof: proof,
        }
    }
    fn verify_single(
        &self,
        transcript: &mut Transcript,
        pk: &PublicKey,
        n: usize,
        commitment: &RistrettoPoint,
    ) -> Result<(), ProofError> {
        // get challenges
        transcript.validate_and_append_point(b"A", &self.A)?;
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        // decompress A
        let As = match self.A.decompress() {
            Some(point) => point,
            None => panic!("fail to decompress"),
        };
        // compute exponent of A_hat
        let one = Scalar::one();
        let two = Scalar::from(2u64);
        let power_of_two: Vec<Scalar> = util::exp_iter_type1(Scalar::from(2u64)).take(n).collect();
        let power_of_y: Vec<Scalar> = util::exp_iter_type2(y).take(n).collect();
        let power_of_y_rev: Vec<Scalar> = power_of_y
            .clone()
            .into_iter()
            .rev()
            .collect::<Vec<Scalar>>();
        let G_exp: Vec<Scalar> = vec![-z; n];
        let H_exp: Vec<Scalar> = power_of_two
            .iter()
            .zip(power_of_y_rev.iter())
            .map(|(power_of_two_i, power_of_y_rev_i)| power_of_two_i * power_of_y_rev_i + z)
            .collect();
        let V_exp = util::scalar_exp_vartime(&y, (n + 1) as u64);
        let mut g_exp: Scalar = power_of_y.iter().sum();
        g_exp *= z - z * z;
        g_exp -= (util::scalar_exp_vartime(&two, n as u64) - one) * V_exp * z;
        self.proof.verify(
            transcript,
            &pk,
            &power_of_y,
            &G_exp,
            &H_exp,
            &g_exp,
            &[V_exp],
            As,
            &[*commitment]
        )
    }
    fn verify_multiple(
        &self,
        transcript: &mut Transcript,
        pk: &PublicKey,
        n: usize,
        m: usize,
        commitment_vec: &[RistrettoPoint],
    ) -> Result<(), ProofError> {
        let mn = n * m;
        // get challenge
        transcript.validate_and_append_point(b"A", &self.A)?;
        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        // decompress A
        let As = match self.A.decompress() {
            Some(point) => point,
            None => panic!("fail to decompress"),
        };
        // compute d
        let power_of_two: Vec<Scalar> = util::exp_iter_type1(Scalar::from(2u64)).take(n).collect();
        let power_of_y: Vec<Scalar> = util::exp_iter_type2(y).take(mn).collect();
        let power_of_y_rev: Vec<Scalar> = power_of_y
            .clone()
            .into_iter()
            .rev()
            .collect::<Vec<Scalar>>();
        let z_sqr = z * z;
        let power_of_z: Vec<Scalar> = util::exp_iter_type2(z_sqr).take(m).collect();
        let d: Vec<Scalar> = power_of_z
            .iter()
            .flat_map(|exp_z| power_of_two.iter().map(move |exp_2| exp_2 * exp_z))
            .collect();
        // compute A_hat exp
        let G_exp: Vec<Scalar> = vec![-z; mn];
        let H_exp: Vec<Scalar> = d
            .iter()
            .zip(power_of_y_rev.iter())
            .map(|(d_i, power_of_y_rev_i)| d_i * power_of_y_rev_i + z)
            .collect();
        let power_of_y_mn_plus_1 = util::scalar_exp_vartime(&y, (mn + 1) as u64);
        let V_exp: Vec<Scalar> = power_of_z
            .iter()
            .map(|power_of_z_i| power_of_z_i * power_of_y_mn_plus_1)
            .collect();
        let mut g_exp: Scalar = power_of_y.iter().sum();
        g_exp *= z - z_sqr;
        let d_sum: Scalar = d.iter().sum();
        g_exp -= d_sum * power_of_y_mn_plus_1 * z;
        self.proof.verify(
            transcript,
            &pk,
            &power_of_y,
            &G_exp,
            &H_exp,
            &g_exp,
            &V_exp,
            As,
            &commitment_vec,
        )
    }
    //
    pub fn size(&self) -> usize {
        let mut res: usize = 0;
        res += mem::size_of_val(self.A.as_bytes());
        res += self.proof.size();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(dead_code)]
    fn range_proof(
        n: usize,
        m: usize,
    ) {
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
    #[test]
    fn test_range_proof_all() {
        range_proof(32 as usize, 1 as usize);
        range_proof(32 as usize, 2 as usize);
        range_proof(32 as usize, 4 as usize);
        range_proof(32 as usize, 8 as usize);
        range_proof(64 as usize, 1 as usize);
        range_proof(64 as usize, 2 as usize);
        range_proof(64 as usize, 4 as usize);
        range_proof(64 as usize, 8 as usize);
    }
}
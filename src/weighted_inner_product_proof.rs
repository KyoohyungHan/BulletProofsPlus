#![allow(non_snake_case)]

extern crate alloc;
extern crate hex;

use alloc::vec::Vec;
use core::iter;
use rand_core::OsRng;
use std::mem;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;

use crate::errors::ProofError;
use crate::publickey::PublicKey;
use crate::transcript::TranscriptProtocol;
use crate::util::weighted_inner_product;

/**
 * Wieghted inner product proof
 * The size of the proof is
 *   2 * log_2{n} + 2 : CompressedRistretto,
 *   3 : Scalar
 */
#[derive(Clone, Debug)]
pub struct WeightedInnerProductProof {
    pub(crate) L_vec: Vec<CompressedRistretto>,
    pub(crate) R_vec: Vec<CompressedRistretto>,
    pub(crate) A: CompressedRistretto,
    pub(crate) B: CompressedRistretto,
    pub(crate) r_prime: Scalar,
    pub(crate) s_prime: Scalar,
    pub(crate) d_prime: Scalar,
}

impl WeightedInnerProductProof {
    /**
     * Prove weighted inner product
     */
    pub fn prove(
        transcript: &mut Transcript,
        pk: &PublicKey,
        a_vec: &Vec<Scalar>,
        b_vec: &Vec<Scalar>,
        power_of_y_vec: &Vec<Scalar>,
        gamma: Scalar,
        commitment: RistrettoPoint,
    ) -> Self {
        // random number generator
        let mut csprng = OsRng;
        // create slices G, H, a, b, c
        let mut G = &mut pk.G_vec.clone()[..];
        let mut H = &mut pk.H_vec.clone()[..];
        let mut a = &mut a_vec.clone()[..];
        let mut b = &mut b_vec.clone()[..];
        let mut power_of_y = &mut power_of_y_vec.clone()[..];
        // create copyed mutable scalars
        let mut alpha = gamma;
        // create copyed mutable commitment
        let mut P = commitment;
        // all of the input vectors must have the same length
        let mut n = G.len();
        assert_eq!(H.len(), n);
        assert_eq!(a.len(), n);
        assert_eq!(b.len(), n);
        assert_eq!(power_of_y.len(), n);
        // the length should be power of two
        assert!(n.is_power_of_two());
        // set transcript weight vector
        transcript.weighted_inner_product_domain_sep(power_of_y_vec);
        // allocate memory for L_vec and R_vec
        let logn = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec: Vec<CompressedRistretto> = Vec::with_capacity(logn);
        let mut R_vec: Vec<CompressedRistretto> = Vec::with_capacity(logn);
        // n > 1 case
        while n != 1 {
            n = n / 2;
            // split a, b, c, G, H vector
            let (a1, a2) = a.split_at_mut(n);
            let (b1, b2) = b.split_at_mut(n);
            let (power_of_y1, power_of_y2) = power_of_y.split_at_mut(n);
            let (G1, G2) = G.split_at_mut(n);
            let (H1, H2) = H.split_at_mut(n);
            // compute c_L and c_R
            let c_L = weighted_inner_product(&a1, &b2, &power_of_y1);
            let c_R = weighted_inner_product(&a2, &b1, &power_of_y2);
            // random d_L and d_R by prover
            let d_L: Scalar = Scalar::random(&mut csprng);
            let d_R: Scalar = Scalar::random(&mut csprng);
            // compute L and R
            let y_nhat = power_of_y1[n - 1];
            let y_nhat_inv = y_nhat.invert();
            let G1_exp: Vec<Scalar> = a2.iter().map(|a2_i| y_nhat * a2_i).collect();
            let G2_exp: Vec<Scalar> = a1.iter().map(|a1_i| y_nhat_inv * a1_i).collect();
            let scalars = G2_exp
                .iter()
                .chain(b2.iter())
                .chain(iter::once(&c_L))
                .chain(iter::once(&d_L));
            let points = G2
                .iter()
                .chain(H1.iter())
                .chain(iter::once(&pk.g))
                .chain(iter::once(&pk.h));
            let L = RistrettoPoint::vartime_multiscalar_mul(scalars, points);
            let scalars = G1_exp
                .iter()
                .chain(b1.iter())
                .chain(iter::once(&c_R))
                .chain(iter::once(&d_R));
            let points = G1
                .iter()
                .chain(H2.iter())
                .chain(iter::once(&pk.g))
                .chain(iter::once(&pk.h));
            let R = RistrettoPoint::vartime_multiscalar_mul(scalars, points);
            L_vec.push(L.compress());
            R_vec.push(R.compress());
            // get challenge e
            transcript.append_point(b"L", &(L.compress()));
            transcript.append_point(b"R", &(R.compress()));
            let e = transcript.challenge_scalar(b"e");
            let e_inv = e.invert();
            let e_sqr = e * e;
            let e_sqr_inv = e_inv * e_inv;
            // update a, b, c, alpha, G, H, P
            P = P + RistrettoPoint::vartime_multiscalar_mul(&[e_sqr, e_sqr_inv], &[L, R]);
            let y_nhat_e_inv = y_nhat * e_inv;
            let y_nhat_inv_e = y_nhat_inv * e;
            for i in 0..n {
                a1[i] = a1[i] * e + a2[i] * y_nhat_e_inv;
                b1[i] = b1[i] * e_inv + b2[i] * e;
                G1[i] = RistrettoPoint::vartime_multiscalar_mul(
                    &[e_inv, y_nhat_inv_e],
                    &[G1[i], G2[i]],
                );
                H1[i] = RistrettoPoint::vartime_multiscalar_mul(&[e, e_inv], &[H1[i], H2[i]]);
            }
            a = a1;
            b = b1;
            power_of_y = power_of_y1;
            G = G1;
            H = H1;
            alpha += e_sqr * d_L + e_sqr_inv * d_R;
        }
        // random r, s, delta, eta
        let r: Scalar = Scalar::random(&mut csprng);
        let s: Scalar = Scalar::random(&mut csprng);
        let delta: Scalar = Scalar::random(&mut csprng);
        let eta: Scalar = Scalar::random(&mut csprng);
        // compute A and B
        let rcbsca = r * power_of_y[0] * b[0] + s * power_of_y[0] * a[0];
        let rcs = r * power_of_y[0] * s;
        let A = RistrettoPoint::vartime_multiscalar_mul(
            &[r, s, rcbsca, delta],
            &[G[0], H[0], pk.g, pk.h],
        )
        .compress();
        let B = RistrettoPoint::vartime_multiscalar_mul(
            &[rcs, eta],
            &[pk.g, pk.h],
        ).compress();
        // get challenge e
        transcript.append_point(b"A", &A);
        transcript.append_point(b"B", &B);
        let e = transcript.challenge_scalar(b"e");
        // compute r_prime, s_prime, delta_prime
        let r_prime = r + a[0] * e;
        let s_prime = s + b[0] * e;
        let d_prime = eta + delta * e + alpha * e * e;
        WeightedInnerProductProof {
            L_vec: L_vec,
            R_vec: R_vec,
            A: A,
            B: B,
            r_prime: r_prime,
            s_prime: s_prime,
            d_prime: d_prime,
        }
    }
    /**
     * To represent all verification process in one
     * multi-exponentiation, this function gets exponents
     * of commitment which can be computted publicly.
     *
     * Commitment = A' + Sum G_exp[i] * G_vec[i]
     *             + Sum H_exp[i] * H_vec[i]
     *             + g_exp * g + Sum V_exp * V
     */
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        pk: &PublicKey,
        power_of_y_vec: &Vec<Scalar>,
        G_exp_of_commitment: &[Scalar],
        H_exp_of_commitment: &[Scalar],
        g_exp_of_commitment: &Scalar,
        V_exp_of_commitment: &[Scalar],
        A_prime: RistrettoPoint,
        V: &[RistrettoPoint],
    ) -> Result<(), ProofError> {
        use curve25519_dalek::traits::IsIdentity;
        let logn = self.L_vec.len();
        let n = (1 << logn) as usize;
        // set transcript weight vector
        transcript.weighted_inner_product_domain_sep(power_of_y_vec);
        // get challenge vector
        let mut challenges = Vec::with_capacity(logn);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            transcript.validate_and_append_point(b"L", L)?;
            transcript.validate_and_append_point(b"R", R)?;
            challenges.push(transcript.challenge_scalar(b"e"));
        }
        let mut challenges_inv = challenges.clone();
        let allinv = Scalar::batch_invert(&mut challenges_inv);
        // compute square of challenges
        for i in 0..logn {
            challenges[i] = challenges[i] * challenges[i];
            challenges_inv[i] = challenges_inv[i] * challenges_inv[i];
        }
        let challenges_sqr = challenges;
        let challenges_inv_sqr = challenges_inv;
        // compute (c0/c0, c0/c1, c0/c2, ...) for ci = y^{i+1}
        let mut power_of_y_vec_inv = power_of_y_vec.clone();
        let _ = Scalar::batch_invert(&mut power_of_y_vec_inv);
        let power_of_y_vec_inv: Vec<Scalar> = power_of_y_vec_inv
            .iter()
            .map(|power_of_y_vec_inv_i| power_of_y_vec_inv_i * power_of_y_vec[0])
            .collect();
        // get the last challenge
        transcript.validate_and_append_point(b"A", &self.A)?;
        transcript.validate_and_append_point(b"B", &self.B)?;
        let e = transcript.challenge_scalar(b"e");
        let e_sqr = e * e;
        // compute s and s' vector
        let mut s_vec = Vec::with_capacity(n);
        s_vec.push(allinv);
        for i in 1..n {
            let log_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << log_i;
            let u_log_i_sq = challenges_sqr[(logn - 1) - log_i];
            s_vec.push(s_vec[i - k] * u_log_i_sq);
        }
        let s_prime_vec: Vec<Scalar> = s_vec.clone().into_iter().rev().collect();
        for i in 1..n {
            s_vec[i] *= power_of_y_vec_inv[i];
        }
        // compute RHS / LHS
        let Ls_exp = challenges_sqr
            .iter()
            .map(|challenges_sqr_i| challenges_sqr_i * e_sqr);
        let Rs_exp = challenges_inv_sqr
            .iter()
            .map(|challenges_inv_sqr_i| challenges_inv_sqr_i * e_sqr);
        let G_exp = s_vec
            .iter()
            .zip(G_exp_of_commitment.iter())
            .map(|(s_vec_i, g_exp_of_comm_i)| {
                -s_vec_i * self.r_prime * e + g_exp_of_comm_i * e_sqr
            });
        let H_exp = s_prime_vec.iter().zip(H_exp_of_commitment.iter()).map(
            |(s_prime_vec_i, h_exp_of_comm_i)| {
                -s_prime_vec_i * self.s_prime * e + h_exp_of_comm_i * e_sqr
            },
        );
        let g_exp = -self.r_prime * power_of_y_vec[0] * self.s_prime + *g_exp_of_commitment * e_sqr;
        let h_exp = -self.d_prime;
        let V_exp = V_exp_of_commitment
            .iter()
            .map(|V_exp_of_commitment_i| V_exp_of_commitment_i * e_sqr);
        let expected = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(e))
                .chain(iter::once(e_sqr))
                .chain(iter::once(g_exp))
                .chain(iter::once(h_exp))
                .chain(Ls_exp)
                .chain(Rs_exp)
                .chain(G_exp)
                .chain(H_exp)
                .chain(V_exp),
            iter::once(self.B.decompress())
                .chain(iter::once(self.A.decompress()))
                .chain(iter::once(Some(A_prime)))
                .chain(iter::once(Some(pk.g)))
                .chain(iter::once(Some(pk.h)))
                .chain(self.L_vec.iter().map(|L| L.decompress()))
                .chain(self.R_vec.iter().map(|R| R.decompress()))
                .chain(pk.G_vec.iter().map(|&x| Some(x)))
                .chain(pk.H_vec.iter().map(|&x| Some(x)))
                .chain(V.iter().map(|&v| Some(v))),
        )
        .ok_or_else(|| ProofError::VerificationError)?;
        // check LSH == RHS
        if expected.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
    //
    pub fn size(&self) -> usize {
        let n = self.L_vec.len();
        let mut res: usize = 0;
        for i in 0..n {
            res += mem::size_of_val(self.L_vec[i].as_bytes());
            res += mem::size_of_val(self.R_vec[i].as_bytes());
        }
        res += mem::size_of_val(self.A.as_bytes());
        res += mem::size_of_val(self.B.as_bytes());
        res += mem::size_of_val(self.r_prime.as_bytes());
        res += mem::size_of_val(self.s_prime.as_bytes());
        res += mem::size_of_val(self.d_prime.as_bytes());
        res
    }
}

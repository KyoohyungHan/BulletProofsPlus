#![allow(non_snake_case)]

extern crate alloc;

use core::iter;
use alloc::vec::Vec;
use rand_core::OsRng;

use curve25519_dalek::ristretto::{RistrettoPoint, VartimeRistrettoPrecomputation};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimePrecomputedMultiscalarMul;

/**
 * Publickey 
 */
pub struct PublicKey {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub G_vec: Vec<RistrettoPoint>,
    pub H_vec: Vec<RistrettoPoint>,
    pub precomputed_table1: VartimeRistrettoPrecomputation,
    pub precomputed_table2: VartimeRistrettoPrecomputation,
}

impl PublicKey {
    //
    pub fn new(length: usize) -> Self {
        let mut csprng = OsRng;
        let g = RistrettoPoint::random(&mut csprng);
        let h = RistrettoPoint::random(&mut csprng);
        let G_vec: Vec<RistrettoPoint> = (0..length)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        let H_vec: Vec<RistrettoPoint> = (0..length)
            .map(|_| RistrettoPoint::random(&mut csprng))
            .collect();
        // pre-compute for a * g + b * h computation
        let precomputed_table1 = VartimeRistrettoPrecomputation::new(
            iter::once(&g)
            .chain(iter::once(&h))
        );
        // pre-compute for Sum a_i G_i + Sum b_i H_i + x * g + y * h
        let precomputed_table2 = VartimeRistrettoPrecomputation::new(
            G_vec.iter().cloned()
            .chain(H_vec.iter().cloned())
            .chain(iter::once(g))
            .chain(iter::once(h))
        );
        PublicKey {
            g: g,
            h: h,
            G_vec: G_vec,
            H_vec: H_vec,
            precomputed_table1: precomputed_table1,
            precomputed_table2: precomputed_table2,
        }
    }
    //
    pub fn commitment(&self, v: &Scalar, gamma: &Scalar) -> RistrettoPoint {
        self.precomputed_table1.vartime_multiscalar_mul(&[*v, *gamma])
    }
    //
    pub fn vector_commitment(
        &self,
        a_vec: &Vec<Scalar>,
        b_vec: &Vec<Scalar>,
        out: &Scalar,
        gamma: &Scalar,
    ) -> RistrettoPoint {
        let scalars = a_vec
            .iter()
            .chain(b_vec.iter())
            .chain(iter::once(out))
            .chain(iter::once(gamma));
        self.precomputed_table2.vartime_multiscalar_mul(scalars)
    }
}
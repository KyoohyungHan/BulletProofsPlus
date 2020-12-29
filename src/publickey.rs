#![allow(non_snake_case)]

extern crate alloc;

use core::iter;
use alloc::vec::Vec;
use rand_core::OsRng;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

/**
 * Publickey 
 */
pub struct PublicKey {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub G_vec: Vec<RistrettoPoint>,
    pub H_vec: Vec<RistrettoPoint>,
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
        PublicKey {
            g: g,
            h: h,
            G_vec: G_vec,
            H_vec: H_vec,
        }
    }
    //
    pub fn commitment(&self, v: &Scalar, gamma: &Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(&[*v, *gamma], &[self.g, self.h])
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
        let points = self.G_vec.iter()
            .chain(self.H_vec.iter())
            .chain(iter::once(&self.g))
            .chain(iter::once(&self.h));
            RistrettoPoint::multiscalar_mul(scalars, points)
    }
}
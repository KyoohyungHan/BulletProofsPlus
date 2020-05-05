#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint;

pub struct RangeVerifier {
    pub commitment_vec: Vec<RistrettoPoint>,
}

impl RangeVerifier {
    //
    pub fn new() -> Self {
        RangeVerifier {
            commitment_vec: Vec::new(),
        }
    }
    //
    pub fn allocate(
        &mut self,
        commitment: &Vec<RistrettoPoint>,
    ) {
        self.commitment_vec = commitment.clone();
    }
}
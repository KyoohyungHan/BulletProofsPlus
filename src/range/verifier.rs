#![allow(non_snake_case)]
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

pub struct RangeVerifier {
    pub commitment_vec: Vec<CompressedRistretto>,
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
        commitment: &Vec<CompressedRistretto>,
    ) {
        self.commitment_vec = commitment.clone();
        // self.commitment_vec = commitment.clone().iter().map(|V| V.compress()).collect();
    }
}
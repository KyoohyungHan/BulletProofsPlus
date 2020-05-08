#![allow(non_snake_case)]

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;

use crate::publickey::PublicKey;

/**
 * Range Prover which contains witness 
 */
pub struct RangeProver {
    pub(crate) v_vec: Vec<u64>,
    pub(crate) gamma_vec: Vec<Scalar>,
    pub commitment_vec: Vec<RistrettoPoint>,
}

impl RangeProver {
    //
    pub fn new() -> Self {
        RangeProver {
            v_vec: Vec::new(),
            gamma_vec: Vec::new(),
            commitment_vec: Vec::new(),
        }
    }
    //
    pub fn commit(
        &mut self,
        pk: &PublicKey,
        v: u64,
        gamma: Scalar,
    ) {
        self.v_vec.push(v);
        self.gamma_vec.push(gamma);
        self.commitment_vec.push(pk.commitment(&Scalar::from(v), &gamma));
    }
}
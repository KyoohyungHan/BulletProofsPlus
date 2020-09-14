/**
 * This code is mostly copied from
 * https://github.com/dalek-cryptography/bulletproofs
 */

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::errors::ProofError;

pub trait TranscriptProtocol {
    fn weighted_inner_product_domain_sep(
        &mut self,
        weights: &[Scalar]);
    fn rangeproof_domain_sep(
        &mut self,
        n: u64,
        m: u64);
    fn innerproduct_domain_sep(
        &mut self,
        n: u64);
    fn r1cs_domain_sep(&mut self);
    fn append_scalar(
        &mut self,
        label:
        &'static [u8],
        scalar: &Scalar);
    fn append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto);
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError>;
    fn challenge_scalar(
        &mut self,
        label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64) {
        self.append_message(b"dom-sep", b"rangeproof v1");
        self.append_u64(b"n", n);
        self.append_u64(b"m", m);
    }
    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ipp v1");
        self.append_u64(b"n", n);
    }
    fn weighted_inner_product_domain_sep(&mut self, weights: &[Scalar]) {
        self.append_message(b"dom-sep", b"wipp v1");
        let n = weights.len();
        for i in 0..n {
            self.append_message(b"weights", weights[i].as_bytes());
        }
        self.append_u64(b"n", n as u64);
    }
    fn r1cs_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"r1cs v1");
    }
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError> {
        use curve25519_dalek::traits::IsIdentity;
        if point.is_identity() {
            Err(ProofError::VerificationError)
        } else {
            Ok(self.append_message(label, point.as_bytes()))
        }
    }
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

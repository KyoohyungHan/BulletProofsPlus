#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use super::{ConstraintSystem, LinearCombination, Variable};
use crate::errors::R1CSError;

/**
 * R1CS Verifier which containts
 * constraints system 
 */
pub struct R1CSVerifier {
    pub constraints: Vec<LinearCombination>,
    pub num_vars: usize,
    pub commitment_vec: Vec<RistrettoPoint>,
    pending_multiplier: Option<usize>,
}

impl ConstraintSystem for R1CSVerifier {
    fn new() -> Self {
        R1CSVerifier {
            constraints: Vec::new(),
            commitment_vec: Vec::new(),
            num_vars: 0 as usize,
            pending_multiplier: None,
        }
    }
    //
    fn multiply(
        &mut self,
        mut left: LinearCombination,
        mut right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        let var = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        // Constrain l,r,o:
        left.terms.push((l_var, -Scalar::one()));
        right.terms.push((r_var, -Scalar::one()));
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }
    //
    fn allocate(&mut self, _: Option<Scalar>) -> Result<Variable, R1CSError> {
        match self.pending_multiplier {
            None => {
                let i = self.num_vars;
                self.num_vars += 1;
                self.pending_multiplier = Some(i);
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                Ok(Variable::MultiplierRight(i))
            }
        }
    }
    //
    fn allocate_multiplier(
        &mut self,
        _: Option<(Scalar, Scalar)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        let var = self.num_vars;
        self.num_vars += 1;

        // Create variables for l,r,o
        let l_var = Variable::MultiplierLeft(var);
        let r_var = Variable::MultiplierRight(var);
        let o_var = Variable::MultiplierOutput(var);

        Ok((l_var, r_var, o_var))
    }
    //
    fn multipliers_len(&self) -> usize {
        self.num_vars
    }
    //
    fn constrain(&mut self, lc: LinearCombination) {
        self.constraints.push(lc);
    }
}

impl R1CSVerifier {
    //
    pub fn commit(
        &mut self,
        commitment: RistrettoPoint,
    ) -> Variable {
        let i = self.commitment_vec.len();
        self.commitment_vec.push(commitment);
        Variable::Committed(i)
    }
    //
    pub(crate) fn flattened_constraints(
        &self,
        y: &Scalar,
        z: &Scalar,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar) {
        let n = self.num_vars;
        let m = self.commitment_vec.len();

        let mut zQ_WL = vec![Scalar::zero(); n];
        let mut zQ_WR = vec![Scalar::zero(); n];
        let mut zQ_WO = vec![Scalar::zero(); n];
        let mut zQ_WV = vec![Scalar::zero(); m];
        let mut zQ_C = Scalar::zero();

        let z_sqr = z * z;
        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var {
                    Variable::MultiplierLeft(i) => {
                        zQ_WL[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierRight(i) => {
                        zQ_WR[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierOutput(i) => {
                        zQ_WO[*i] += exp_z * coeff;
                    }
                    Variable::Committed(i) => {
                        zQ_WV[*i] -= exp_z * coeff;
                    }
                    Variable::One() => {
                        zQ_C -= exp_z * coeff;
                    }
                }
            }
            exp_z *= z_sqr;
        }
        let y_inv = y.invert();
        let mut power_of_y_inv: Vec<Scalar> = Vec::with_capacity(n);
        power_of_y_inv.push(y_inv);
        for i in 1..n {
            power_of_y_inv.push(power_of_y_inv[i - 1] * y_inv);
        }
        let T_WL: Vec<Scalar> = zQ_WL
            .iter()
            .zip(power_of_y_inv.iter())
            .map(|(zQ_WL_i, power_of_y_inv_i)| zQ_WL_i * power_of_y_inv_i)
            .collect();
        let T_WR: Vec<Scalar> = zQ_WR
            .iter()
            .zip(power_of_y_inv.iter())
            .map(|(zQ_WR_i, power_of_y_inv_i)| zQ_WR_i * power_of_y_inv_i)
            .collect();
        let T_WO: Vec<Scalar> = zQ_WO
            .iter()
            .zip(power_of_y_inv.iter())
            .map(|(zQ_WO_i, power_of_y_inv_i)| zQ_WO_i * power_of_y_inv_i)
            .collect();

        (T_WL, T_WR, T_WO, zQ_WV, zQ_C)
    }
    //
}
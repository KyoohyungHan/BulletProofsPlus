#![allow(non_snake_case)]

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use super::{ConstraintSystem, LinearCombination, Variable};
use crate::errors::R1CSError;
use crate::publickey::PublicKey;

/**
 * R1CS Prover which contains witness and
 * constraints system  
 */
pub struct R1CSProver {
    pub(super) constraints: Vec<LinearCombination>,
    pub(super) a_L: Vec<Scalar>,
    pub(super) a_R: Vec<Scalar>,
    pub(super) a_O: Vec<Scalar>,
    pub(super) v_vec: Vec<Scalar>,
    pub(super) gamma_vec: Vec<Scalar>,
    pub commitment_vec: Vec<RistrettoPoint>,
    pending_multiplier: Option<usize>,
}

impl ConstraintSystem for R1CSProver {
    fn new() -> Self {
        R1CSProver {
            constraints: Vec::new(),
            a_L: Vec::new(),
            a_R: Vec::new(),
            a_O: Vec::new(),
            v_vec: Vec::new(),
            gamma_vec: Vec::new(),
            commitment_vec: Vec::new(),
            pending_multiplier: None,
        }
    }
    //
    fn multiply(
        &mut self,
        mut left: LinearCombination,
        mut right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        let l = self.eval(&left);
        let r = self.eval(&right);
        let o = l * r;
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);
        left.terms.push((l_var, -Scalar::one()));
        right.terms.push((r_var, -Scalar::one()));
        self.constrain(left);
        self.constrain(right);
        (l_var, r_var, o_var)
    }
    //
    fn allocate(
        &mut self,
        assignment: Option<Scalar>
    ) -> Result<Variable, R1CSError> {
        let scalar = assignment.ok_or(R1CSError::MissingAssignment)?;

        match self.pending_multiplier {
            None => {
                let i = self.a_L.len();
                self.pending_multiplier = Some(i);
                self.a_L.push(scalar);
                self.a_R.push(Scalar::zero());
                self.a_O.push(Scalar::zero());
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                self.a_R[i] = scalar;
                self.a_O[i] = self.a_L[i] * self.a_R[i];
                Ok(Variable::MultiplierRight(i))
            }
        }
    }
    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(Scalar, Scalar)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        let (l, r) = input_assignments.ok_or(R1CSError::MissingAssignment)?;
        let o = l * r;
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);
        Ok((l_var, r_var, o_var))
    }
    //
    fn multipliers_len(&self) -> usize {
        self.a_L.len()
    }
    //
    fn constrain(&mut self, lc: LinearCombination) {
        self.constraints.push(lc);
    }
}

impl R1CSProver {
    //
    pub fn commit(
        &mut self,
        pk: &PublicKey,
        v: Scalar,
        gamma: Scalar,
    ) -> (RistrettoPoint, Variable) {
        let i = self.v_vec.len();
        self.v_vec.push(v);
        self.gamma_vec.push(gamma);
        let V = pk.commitment(&v, &gamma);
        self.commitment_vec.push(V);
        (V, Variable::Committed(i))
    }
    //
    pub fn flattened_constraints(
        &self,
        y: &Scalar,
        z: &Scalar,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar) {
        let n = self.a_L.len();
        let m = self.v_vec.len();

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
    fn eval(&self, lc: &LinearCombination) -> Scalar {
        lc.terms
            .iter()
            .map(|(var, coeff)| {
                coeff
                    * match var {
                        Variable::MultiplierLeft(i) => self.a_L[*i],
                        Variable::MultiplierRight(i) => self.a_R[*i],
                        Variable::MultiplierOutput(i) => self.a_O[*i],
                        Variable::Committed(i) => self.v_vec[*i],
                        Variable::One() => Scalar::one(),
                    }
            })
            .sum()
    }
}
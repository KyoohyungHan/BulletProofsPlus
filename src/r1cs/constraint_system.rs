use super::{LinearCombination, Variable};
use curve25519_dalek::scalar::Scalar;
use crate::errors::R1CSError;

pub trait ConstraintSystem {
    fn new() -> Self;
    //
    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable);
    //
    fn allocate(
        &mut self,
        assignment: Option<Scalar>
    ) -> Result<Variable, R1CSError>;
    //
    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(Scalar, Scalar)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError>;
    //
    fn multipliers_len(&self) -> usize;
    //
    fn constrain(&mut self, lc: LinearCombination);
    //
}
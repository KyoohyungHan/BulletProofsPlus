use curve25519_dalek::scalar::Scalar;
use std::iter::FromIterator;
use std::ops::{Add, Mul, Neg, Sub};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Variable {
    Committed(usize),
    MultiplierLeft(usize),
    MultiplierRight(usize),
    MultiplierOutput(usize),
    One(),
}

impl From<Variable> for LinearCombination {
    fn from(v: Variable) -> LinearCombination {
        LinearCombination {
            terms: vec![(v, Scalar::one())],
        }
    }
}

impl<S: Into<Scalar>> From<S> for LinearCombination {
    fn from(s: S) -> LinearCombination {
        LinearCombination {
            terms: vec![(Variable::One(), s.into())],
        }
    }
}

impl Neg for Variable {
    type Output = LinearCombination;

    fn neg(self) -> Self::Output {
        -LinearCombination::from(self)
    }
}

impl<L: Into<LinearCombination>> Add<L> for Variable {
    type Output = LinearCombination;

    fn add(self, other: L) -> Self::Output {
        LinearCombination::from(self) + other.into()
    }
}

impl<L: Into<LinearCombination>> Sub<L> for Variable {
    type Output = LinearCombination;

    fn sub(self, other: L) -> Self::Output {
        LinearCombination::from(self) - other.into()
    }
}

impl<S: Into<Scalar>> Mul<S> for Variable {
    type Output = LinearCombination;

    fn mul(self, other: S) -> Self::Output {
        LinearCombination {
            terms: vec![(self, other.into())],
        }
    }
}

impl Add<Variable> for Scalar {
    type Output = LinearCombination;

    fn add(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(Variable::One(), self), (other, Scalar::one())],
        }
    }
}

impl Sub<Variable> for Scalar {
    type Output = LinearCombination;

    fn sub(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(Variable::One(), self), (other, -Scalar::one())],
        }
    }
}

impl Mul<Variable> for Scalar {
    type Output = LinearCombination;

    fn mul(self, other: Variable) -> Self::Output {
        LinearCombination {
            terms: vec![(other, self)],
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LinearCombination {
    pub(super) terms: Vec<(Variable, Scalar)>,
}

impl Default for LinearCombination {
    fn default() -> Self {
        LinearCombination { terms: Vec::new() }
    }
}

impl FromIterator<(Variable, Scalar)> for LinearCombination {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (Variable, Scalar)>,
    {
        LinearCombination {
            terms: iter.into_iter().collect(),
        }
    }
}

impl<'a> FromIterator<&'a (Variable, Scalar)> for LinearCombination {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = &'a (Variable, Scalar)>,
    {
        LinearCombination {
            terms: iter.into_iter().cloned().collect(),
        }
    }
}

impl<L: Into<LinearCombination>> Add<L> for LinearCombination {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms.iter().cloned());
        LinearCombination { terms: self.terms }
    }
}

impl<L: Into<LinearCombination>> Sub<L> for LinearCombination {
    type Output = Self;

    fn sub(mut self, rhs: L) -> Self::Output {
        self.terms
            .extend(rhs.into().terms.iter().map(|(var, coeff)| (*var, -coeff)));
        LinearCombination { terms: self.terms }
    }
}

impl Mul<LinearCombination> for Scalar {
    type Output = LinearCombination;

    fn mul(self, other: LinearCombination) -> Self::Output {
        let out_terms = other
            .terms
            .into_iter()
            .map(|(var, scalar)| (var, scalar * self))
            .collect();
        LinearCombination { terms: out_terms }
    }
}

impl Neg for LinearCombination {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s
        }
        self
    }
}

impl<S: Into<Scalar>> Mul<S> for LinearCombination {
    type Output = Self;

    fn mul(mut self, other: S) -> Self::Output {
        let other = other.into();
        for (_, s) in self.terms.iter_mut() {
            *s *= other
        }
        self
    }
}

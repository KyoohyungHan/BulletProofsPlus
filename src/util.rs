/**
 * This code is mostly copied from
 * https://github.com/dalek-cryptography/bulletproofs
 */

use curve25519_dalek::scalar::Scalar;

pub struct ScalarExp {
    x: Scalar,
    next_exp_x: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;
    fn next(&mut self) -> Option<Scalar> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

#[allow(dead_code)]
pub fn exp_iter_type1(x: Scalar) -> ScalarExp {
    let next_exp_x = Scalar::one();
    ScalarExp { x, next_exp_x }
}

#[allow(dead_code)]
pub fn exp_iter_type2(x: Scalar) -> ScalarExp {
    let next_exp_x = x;
    ScalarExp { x, next_exp_x }
}

#[allow(dead_code)]
pub fn scalar_exp_vartime(x: &Scalar, mut n: u64) -> Scalar {
    let mut result = Scalar::one();
    let mut aux = *x; // x, x^2, x^4, x^8, ...
    while n > 0 {
        let bit = n & 1;
        if bit == 1 {
            result = result * aux;
        }
        n = n >> 1;
        aux = aux * aux;
    }
    result
}

#[allow(dead_code)]
pub fn sum_of_powers_type1(x: &Scalar, n: usize) -> Scalar {
    if !n.is_power_of_two() {
        return sum_of_powers_slow_type1(x, n);
    }
    if n == 0 || n == 1 {
        return Scalar::from(n as u64);
    }
    let mut m = n;
    let mut result = Scalar::one() + x;
    let mut factor = *x;
    while m > 2 {
        factor = factor * factor;
        result = result + factor * result;
        m = m / 2;
    }
    result
}

#[allow(dead_code)]
fn sum_of_powers_slow_type1(x: &Scalar, n: usize) -> Scalar {
    exp_iter_type1(*x).take(n).sum()
}

#[allow(dead_code)]
pub fn sum_of_powers_type2(x: &Scalar, n: usize) -> Scalar {
    if !n.is_power_of_two() {
        return sum_of_powers_slow_type2(x, n);
    }
    if n == 0 || n == 1 {
        return Scalar::from(n as u64);
    }
    let mut m = n;
    let mut result = x + x * x;
    let mut factor = *x;
    while m > 2 {
        factor = factor * factor;
        result = result + factor * result;
        m = m / 2;
    }
    result
}

#[allow(dead_code)]
fn sum_of_powers_slow_type2(x: &Scalar, n: usize) -> Scalar {
    exp_iter_type2(*x).take(n).sum()
}

#[allow(dead_code)]
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::zero();
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

#[allow(dead_code)]
pub fn weighted_inner_product(a: &[Scalar], b: &[Scalar], c: &[Scalar]) -> Scalar {
    let mut out = Scalar::zero();
    for i in 0..a.len() {
        out += a[i] * b[i] * c[i];
    }
    out
}
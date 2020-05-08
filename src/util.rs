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

/**
 * Return an iterator of the (1, x, x^2, ...)
 */
#[allow(dead_code)]
pub fn exp_iter_type1(x: Scalar) -> ScalarExp {
    let next_exp_x = Scalar::one();
    ScalarExp { x, next_exp_x }
}

/**
 * Return an iterator of the powers of (x, x^2, x^3, ...) 
 */
#[allow(dead_code)]
pub fn exp_iter_type2(x: Scalar) -> ScalarExp {
    let next_exp_x = x;
    ScalarExp { x, next_exp_x }
}

/**
 * Return x^n 
 */
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

/**
 * Return inner product between a and b
 */
#[allow(dead_code)]
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::zero();
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

/**
 * Return weighted inner product between a and b with weight c
 */
#[allow(dead_code)]
pub fn weighted_inner_product(a: &[Scalar], b: &[Scalar], c: &[Scalar]) -> Scalar {
    let mut out = Scalar::zero();
    for i in 0..a.len() {
        out += a[i] * b[i] * c[i];
    }
    out
}
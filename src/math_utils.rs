use num_bigint::BigInt;
use num_traits::FromPrimitive;

use crate::bigint;

/// Gets two points on an elliptic curve mod p and returns their sum.
/// Assumes the points are given in affine form (x, y) and have different x coordinates.
pub fn ec_add(
    point_a: (BigInt, BigInt),
    point_b: (BigInt, BigInt),
    prime: BigInt,
) -> (BigInt, BigInt) {
    let m = line_slope(point_a, point_b, prime);
    let x = (m * m - point_a.0 - point_b.0) % prime;
    let y = (m * (point_a.0 - x) - point_b.1) % prime;
    (x, y)
}

/// Computes the slope of the line connecting the two given EC points over the field GF(p).
/// Assumes the points are given in affine form (x, y) and have different x coordinates.
pub fn line_slope(point_a: (BigInt, BigInt), point_b: (BigInt, BigInt), prime: BigInt) -> BigInt {
    assert!((point_a.0 - point_b.0) % prime != bigint!(0));
    (point_a.1 - point_b.1) / (point_a.0 - point_b.0) % prime
}

///  Doubles a point on an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p.
/// Assumes the point is given in affine form (x, y) and has y != 0.
pub fn ec_double(point: (BigInt, BigInt), alpha: BigInt, prime: BigInt) -> (BigInt, BigInt) {
    let m = ec_double_slope(point, alpha, prime);
    let x = ((m * m) - (bigint!(2) * point.0)) % prime;
    let y = (m * (point.0 - x) - point.0) % prime;
    (x, y)
}

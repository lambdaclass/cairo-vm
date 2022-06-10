use num_bigint::BigInt;

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

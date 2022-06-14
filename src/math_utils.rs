use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{abs, FromPrimitive};

use crate::bigint;

fn igcdex(num_a: BigInt, num_b: BigInt) -> (BigInt, BigInt, BigInt) {
    let mut a = num_a;
    let mut b = num_b;
    let x_sign: i32;
    let y_sign: i32;
    match (a.clone(), b.clone()) {
        (a, b) if a == b && a == bigint!(0) => (bigint!(0), bigint!(1), bigint!(0)),
        (a, _) if a == bigint!(0) => (bigint!(0), b.div_floor(&abs(b.clone())), abs(b)),
        (_, b) if b == bigint!(0) => (a.div_floor(&a), bigint!(0), abs(a)),
        _ => {
            if a < bigint!(0) {
                a = -a;
                x_sign = -1;
            } else {
                x_sign = 1;
            }
            if b < bigint!(0) {
                b = -b;
                y_sign = -1;
            } else {
                y_sign = 1;
            }
            let (mut x, mut y, mut r, mut s) = (bigint!(1), bigint!(0), bigint!(0), bigint!(1));
            let (mut c, mut q);
            while b != bigint!(0) {
                (c, q) = (a.clone() % b.clone(), a.div_floor(&b.clone()));
                (a, b, r, s, x, y) = (b, c, x - q.clone() * r.clone(), y - q * s.clone(), r, s)
            }
            (x * x_sign, y * y_sign, a)
        }
    }
}
///Finds a nonnegative integer x < p such that (m * x) % p == n.
fn div_mod(n: BigInt, m: BigInt, p: BigInt) -> BigInt {
    let (a, _, c) = igcdex(m, p.clone());
    assert_eq!(c, bigint!(1));
    (n * a) % p
}

/// Gets two points on an elliptic curve mod p and returns their sum.
/// Assumes the points are given in affine form (x, y) and have different x coordinates.
pub fn ec_add(
    point_a: (BigInt, BigInt),
    point_b: (BigInt, BigInt),
    prime: &BigInt,
) -> (BigInt, BigInt) {
    let m = line_slope(point_a.clone(), point_b.clone(), prime);
    let x = (m.clone() * m.clone() - point_a.0.clone() - point_b.0) % prime;
    let y = (m * (point_a.0 - x.clone()) - point_b.1) % prime;
    (x, y)
}

/// Computes the slope of the line connecting the two given EC points over the field GF(p).
/// Assumes the points are given in affine form (x, y) and have different x coordinates.
pub fn line_slope(point_a: (BigInt, BigInt), point_b: (BigInt, BigInt), prime: &BigInt) -> BigInt {
    assert!((point_a.0.clone() - point_b.0.clone()) % prime != bigint!(0));
    div_mod(point_a.1 - point_b.1, point_a.0 - point_b.0, prime.clone())
}

///  Doubles a point on an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p.
/// Assumes the point is given in affine form (x, y) and has y != 0.
pub fn ec_double(point: (BigInt, BigInt), alpha: &BigInt, prime: &BigInt) -> (BigInt, BigInt) {
    let m = ec_double_slope(point.clone(), alpha, prime);
    let x = ((m.clone() * m.clone()) - (bigint!(2) * point.0.clone())) % prime;
    let y = (m * (point.0.clone() - x.clone()) - point.0) % prime;
    (x, y)
}

/// Computes the slope of an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p, at
/// the given point.
/// Assumes the point is given in affine form (x, y) and has y != 0.
pub fn ec_double_slope(point: (BigInt, BigInt), alpha: &BigInt, prime: &BigInt) -> BigInt {
    assert!(point.1.clone() % prime != bigint!(0));
    div_mod(
        bigint!(3) * point.0.clone() * point.0.clone() + alpha,
        bigint!(2) * point.1,
        prime.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint_str;

    #[test]
    fn calculate_igcdex() {
        let a = bigint_str!(
            b"3443173965374276972000139705137775968422921151703548011275075734291405722262"
        );
        let b = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!((bigint_str!(b"-1688547300931946713657663208540757607205184050780245505361433670721217394901"), bigint_str!(b"1606731415015725997151049087601104361134423282856790368548943305828633315023"), bigint!(1)), igcdex(a, b));
    }

    #[test]
    fn compute_line_slope_for_valid_points() {
        let point_a = (
            bigint_str!(
                b"3139037544796708144595053687182055617920475701120786241351436619796497072089"
            ),
            bigint_str!(
                b"2119589567875935397690285099786081818522144748339117565577200220779667999801"
            ),
        );
        let point_b = (
            bigint_str!(
                b"3324833730090626974525872402899302150520188025637965566623476530814354734325"
            ),
            bigint_str!(
                b"3147007486456030910661996439995670279305852583596209647900952752170983517249"
            ),
        );
        let prime = bigint_str!(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!(
            bigint_str!(
                b"992545364708437554384321881954558327331693627531977596999212637460266617010"
            ),
            line_slope(point_a, point_b, &prime)
        );
    }
}

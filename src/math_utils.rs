use crate::vm::errors::vm_errors::VirtualMachineError;
use big_num::BigNum;
use felt::Felt;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::ops::Shr;

///Returns the integer square root of the nonnegative integer n.
///This is the floor of the exact square root of n.
///Unlike math.sqrt(), this function doesn't have rounding error issues.
pub fn isqrt(n: &BigUint) -> Result<BigUint, VirtualMachineError> {
    /*    # The following algorithm was copied from
    # https://stackoverflow.com/questions/15390807/integer-square-root-in-python.
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    assert x**2 <= n < (x + 1) ** 2
    return x*/

    let mut x = n.clone();
    //n.shr(1) = n.div_floor(2)
    let mut y = (&x + 1_u32).shr(1_u32);

    while y < x {
        x = y;
        y = (&x + n.div_floor(&x)).shr(1_u32);
    }

    if !(&x.pow(2) <= n && n < &(&x + 1_u32).pow(2_u32)) {
        return Err(VirtualMachineError::FailedToGetSqrt(n.clone()));
    };
    Ok(x)
}

/// Performs integer division between x and y; fails if x is not divisible by y.
pub fn safe_div(x: &Felt, y: &Felt) -> Result<Felt, VirtualMachineError> {
    if y.is_zero() {
        return Err(VirtualMachineError::DividedByZero);
    }

    let (q, r) = x.div_mod_floor(y);

    if !r.is_zero() {
        return Err(VirtualMachineError::SafeDivFail(x.clone(), y.clone()));
    }

    Ok(q)
}

/// Performs integer division between x and y; fails if x is not divisible by y.
pub fn safe_div_bignum(x: &BigNum, y: &BigNum) -> Result<BigNum, VirtualMachineError> {
    if y.is_zero() {
        return Err(VirtualMachineError::DividedByZero);
    }

    let (q, r) = x.div_mod_floor(y);

    if !r.is_zero() {
        return Err(VirtualMachineError::SafeDivFailBigNum(x.clone(), y.clone()));
    }

    Ok(q)
}

/// Performs integer division between x and y; fails if x is not divisible by y.
pub fn safe_div_biguint(x: &BigUint, y: &BigUint) -> Result<BigUint, VirtualMachineError> {
    if y.is_zero() {
        return Err(VirtualMachineError::DividedByZero);
    }

    let (q, r) = x.div_mod_floor(y);

    if !r.is_zero() {
        return Err(VirtualMachineError::SafeDivFailBigUint(
            x.clone(),
            y.clone(),
        ));
    }

    Ok(q)
}

/// Performs integer division between x and y; fails if x is not divisible by y.
pub fn safe_div_usize(x: usize, y: usize) -> Result<usize, VirtualMachineError> {
    if y.is_zero() {
        return Err(VirtualMachineError::DividedByZero);
    }

    let (q, r) = x.div_mod_floor(&y);

    if !r.is_zero() {
        return Err(VirtualMachineError::SafeDivFailUsize(x, y));
    }

    Ok(q)
}

///Returns x, y, g such that g = x*a + y*b = gcd(a, b).
fn igcdex(num_a: &BigNum, num_b: &BigNum) -> (BigNum, BigNum, BigNum) {
    match (num_a, num_b) {
        (a, b) if a.is_zero() && b.is_zero() => (BigNum::zero(), BigNum::one(), BigNum::zero()),
        (a, _) if a.is_zero() => (BigNum::zero(), num_b.signum(), num_b.abs()),
        (_, b) if b.is_zero() => (num_a.signum(), BigNum::zero(), num_a.abs()),
        _ => {
            let mut a = num_a.abs();
            let x_sign = num_a.signum();
            let mut b = num_b.abs();
            let y_sign = num_b.signum();
            let (mut x, mut y, mut r, mut s) =
                (BigNum::one(), BigNum::zero(), BigNum::zero(), BigNum::one());
            let (mut c, mut q);
            while !b.is_zero() {
                (q, c) = a.div_mod_floor(&b);
                x -= &q * &r;
                y -= &q * &s;
                (a, b, r, s, x, y) = (b, c, x, y, r, s)
            }
            (x * x_sign, y * y_sign, a)
        }
    }
}

///Finds a nonnegative integer x < p such that (m * x) % p == n.
pub fn div_mod(n: &BigNum, m: &BigNum, p: &BigNum) -> BigNum {
    let (a, _, c) = igcdex(m, p);
    debug_assert_eq!(c, BigNum::one());
    (n * &a).mod_floor(p)
}

pub fn ec_add(
    point_a: (BigNum, BigNum),
    point_b: (BigNum, BigNum),
    prime: &BigNum,
) -> (BigNum, BigNum) {
    let m = line_slope(&point_a, &point_b, prime);
    let x = (m.clone() * m.clone() - point_a.0.clone() - point_b.0).mod_floor(prime);
    let y = (m * (point_a.0 - x.clone()) - point_a.1).mod_floor(prime);
    (x, y)
}

/// Computes the slope of the line connecting the two given EC points over the field GF(p).
/// Assumes the points are given in affine form (x, y) and have different x coordinates.
pub fn line_slope(
    point_a: &(BigNum, BigNum),
    point_b: &(BigNum, BigNum),
    prime: &BigNum,
) -> BigNum {
    debug_assert!(!(&point_a.0 - &point_b.0.mod_floor(prime)).is_zero());
    div_mod(
        &(&point_a.1 - &point_b.1),
        &(&point_a.0 - &point_b.0),
        prime,
    )
}

///  Doubles a point on an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p.
/// Assumes the point is given in affine form (x, y) and has y != 0.
pub fn ec_double(point: (BigNum, BigNum), alpha: &BigNum, prime: &BigNum) -> (BigNum, BigNum) {
    let m = ec_double_slope(&point, alpha, prime);
    let x = ((&m * &m) - (2_i32 * &point.0)).mod_floor(prime);
    let y = (m * (point.0 - &x) - point.1).mod_floor(prime);
    (x, y)
}
/// Computes the slope of an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p, at
/// the given point.
/// Assumes the point is given in affine form (x, y) and has y != 0.
pub fn ec_double_slope(point: &(BigNum, BigNum), alpha: &BigNum, prime: &BigNum) -> BigNum {
    debug_assert!(!point.1.mod_floor(prime).is_zero());
    div_mod(
        &(3_i32 * &point.0 * &point.0 + alpha),
        &(2_i32 * &point.1),
        prime,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::*;
    use big_num::BigNumOps;

    use num_traits::Num;

    #[test]
    fn calculate_divmod_a() {
        let a = bignum_str!(
            "11260647941622813594563746375280766662237311019551239924981511729608487775604310196863705127454617186486639011517352066501847110680463498585797912894788"
        );
        let b = bignum_str!(
            "4020711254448367604954374443741161860304516084891705811279711044808359405970"
        );
        assert_eq!(
            bignum_str!(
                "2904750555256547440469454488220756360634457312540595732507835416669695939476"
            ),
            div_mod(
                &a,
                &b,
                &BigNum::from_str_radix(&felt::PRIME_STR[2..], 16).expect("Couldn't parse prime")
            )
        );
    }

    #[test]
    fn calculate_divmod_b() {
        let a = bignum_str!(
            "29642372811668969595956851264770043260610851505766181624574941701711520154703788233010819515917136995474951116158286220089597404329949295479559895970988"
        );
        let b = bignum_str!(
            "3443173965374276972000139705137775968422921151703548011275075734291405722262"
        );
        assert_eq!(
            bignum_str!(
                "3601388548860259779932034493250169083811722919049731683411013070523752439691"
            ),
            div_mod(
                &a,
                &b,
                &BigNum::from_str_radix(&felt::PRIME_STR[2..], 16).expect("Couldn't parse prime")
            )
        );
    }

    #[test]
    fn calculate_divmod_c() {
        let a = bignum_str!(
            "1208267356464811040667664150251401430616174694388968865551115897173431833224432165394286799069453655049199580362994484548890574931604445970825506916876"
        );
        let b = bignum_str!(
            "1809792356889571967986805709823554331258072667897598829955472663737669990418"
        );
        assert_eq!(
            bignum_str!(
                "1545825591488572374291664030703937603499513742109806697511239542787093258962"
            ),
            div_mod(
                &a,
                &b,
                &BigNum::from_str_radix(&felt::PRIME_STR[2..], 16).expect("Couldn't parse prime")
            )
        );
    }

    #[test]
    fn compute_safe_div() {
        let x = Felt::new(26);
        let y = Felt::new(13);
        assert_eq!(safe_div(&x, &y), Ok(Felt::new(2)));
    }

    #[test]
    fn compute_safe_div_non_divisor() {
        let x = Felt::new(25);
        let y = Felt::new(4);
        assert_eq!(
            safe_div(&x, &y),
            Err(VirtualMachineError::SafeDivFail(
                Felt::new(25),
                Felt::new(4)
            ))
        );
    }

    #[test]
    fn compute_safe_div_by_zero() {
        let x = Felt::new(25);
        let y = Felt::zero();
        assert_eq!(safe_div(&x, &y), Err(VirtualMachineError::DividedByZero));
    }

    #[test]
    fn compute_safe_div_usize() {
        assert_eq!(safe_div_usize(26, 13), Ok(2));
    }

    #[test]
    fn compute_safe_div_usize_non_divisor() {
        assert_eq!(
            safe_div_usize(25, 4),
            Err(VirtualMachineError::SafeDivFailUsize(25, 4))
        );
    }

    #[test]
    fn compute_safe_div_usize_by_zero() {
        assert_eq!(
            safe_div_usize(25, 0),
            Err(VirtualMachineError::DividedByZero)
        );
    }

    #[test]
    fn compute_line_slope_for_valid_points() {
        let point_a = (
            bignum_str!(
                "3139037544796708144595053687182055617920475701120786241351436619796497072089"
            ),
            bignum_str!(
                "2119589567875935397690285099786081818522144748339117565577200220779667999801"
            ),
        );
        let point_b = (
            bignum_str!(
                "3324833730090626974525872402899302150520188025637965566623476530814354734325"
            ),
            bignum_str!(
                "3147007486456030910661996439995670279305852583596209647900952752170983517249"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!(
            bignum_str!(
                "992545364708437554384321881954558327331693627531977596999212637460266617010"
            ),
            line_slope(&point_a, &point_b, &prime)
        );
    }

    #[test]
    fn compute_double_slope_for_valid_point_a() {
        let point = (
            bignum_str!(
                "3143372541908290873737380228370996772020829254218248561772745122290262847573"
            ),
            bignum_str!(
                "1721586982687138486000069852568887984211460575851774005637537867145702861131"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let alpha = BigNum::one();
        assert_eq!(
            bignum_str!(
                "3601388548860259779932034493250169083811722919049731683411013070523752439691"
            ),
            ec_double_slope(&point, &alpha, &prime)
        );
    }

    #[test]
    fn compute_double_slope_for_valid_point_b() {
        let point = (
            bignum_str!(
                "1937407885261715145522756206040455121546447384489085099828343908348117672673"
            ),
            bignum_str!(
                "2010355627224183802477187221870580930152258042445852905639855522404179702985"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let alpha = BigNum::one();
        assert_eq!(
            bignum_str!(
                "2904750555256547440469454488220756360634457312540595732507835416669695939476"
            ),
            ec_double_slope(&point, &alpha, &prime)
        );
    }

    #[test]
    fn calculate_ec_double_for_valid_point_a() {
        let point = (
            bignum_str!(
                "1937407885261715145522756206040455121546447384489085099828343908348117672673"
            ),
            bignum_str!(
                "2010355627224183802477187221870580930152258042445852905639855522404179702985"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let alpha = BigNum::one();
        assert_eq!(
            (
                bignum_str!(
                    "58460926014232092148191979591712815229424797874927791614218178721848875644"
                ),
                bignum_str!(
                    "1065613861227134732854284722490492186040898336012372352512913425790457998694"
                )
            ),
            ec_double(point, &alpha, &prime)
        );
    }

    #[test]
    fn calculate_ec_double_for_valid_point_b() {
        let point = (
            bignum_str!(
                "3143372541908290873737380228370996772020829254218248561772745122290262847573"
            ),
            bignum_str!(
                "1721586982687138486000069852568887984211460575851774005637537867145702861131"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let alpha = BigNum::one();
        assert_eq!(
            (
                bignum_str!(
                    "1937407885261715145522756206040455121546447384489085099828343908348117672673"
                ),
                bignum_str!(
                    "2010355627224183802477187221870580930152258042445852905639855522404179702985"
                )
            ),
            ec_double(point, &alpha, &prime)
        );
    }

    #[test]
    fn calculate_ec_double_for_valid_point_c() {
        let point = (
            bignum_str!(
                "634630432210960355305430036410971013200846091773294855689580772209984122075"
            ),
            bignum_str!(
                "904896178444785983993402854911777165629036333948799414977736331868834995209"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        let alpha = BigNum::one();
        assert_eq!(
            (
                bignum_str!(
                    "3143372541908290873737380228370996772020829254218248561772745122290262847573"
                ),
                bignum_str!(
                    "1721586982687138486000069852568887984211460575851774005637537867145702861131"
                )
            ),
            ec_double(point, &alpha, &prime)
        );
    }

    #[test]
    fn calculate_ec_add_for_valid_points_a() {
        let point_a = (
            bignum_str!(
                "1183418161532233795704555250127335895546712857142554564893196731153957537489"
            ),
            bignum_str!(
                "1938007580204102038458825306058547644691739966277761828724036384003180924526"
            ),
        );
        let point_b = (
            bignum_str!(
                "1977703130303461992863803129734853218488251484396280000763960303272760326570"
            ),
            bignum_str!(
                "2565191853811572867032277464238286011368568368717965689023024980325333517459"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!(
            (
                bignum_str!(
                    "1977874238339000383330315148209250828062304908491266318460063803060754089297"
                ),
                bignum_str!(
                    "2969386888251099938335087541720168257053975603483053253007176033556822156706"
                )
            ),
            ec_add(point_a, point_b, &prime)
        );
    }

    #[test]
    fn calculate_ec_add_for_valid_points_b() {
        let point_a = (
            bignum_str!(
                "3139037544796708144595053687182055617920475701120786241351436619796497072089"
            ),
            bignum_str!(
                "2119589567875935397690285099786081818522144748339117565577200220779667999801"
            ),
        );
        let point_b = (
            bignum_str!(
                "3324833730090626974525872402899302150520188025637965566623476530814354734325"
            ),
            bignum_str!(
                "3147007486456030910661996439995670279305852583596209647900952752170983517249"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!(
            (
                bignum_str!(
                    "1183418161532233795704555250127335895546712857142554564893196731153957537489"
                ),
                bignum_str!(
                    "1938007580204102038458825306058547644691739966277761828724036384003180924526"
                )
            ),
            ec_add(point_a, point_b, &prime)
        );
    }

    #[test]
    fn calculate_ec_add_for_valid_points_c() {
        let point_a = (
            bignum_str!(
                "1183418161532233795704555250127335895546712857142554564893196731153957537489"
            ),
            bignum_str!(
                "1938007580204102038458825306058547644691739966277761828724036384003180924526"
            ),
        );
        let point_b = (
            bignum_str!(
                "1977703130303461992863803129734853218488251484396280000763960303272760326570"
            ),
            bignum_str!(
                "2565191853811572867032277464238286011368568368717965689023024980325333517459"
            ),
        );
        let prime = bignum_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!(
            (
                bignum_str!(
                    "1977874238339000383330315148209250828062304908491266318460063803060754089297"
                ),
                bignum_str!(
                    "2969386888251099938335087541720168257053975603483053253007176033556822156706"
                )
            ),
            ec_add(point_a, point_b, &prime)
        );
    }

    #[test]
    fn calculate_isqrt_a() {
        let n = biguint!(81);
        assert_eq!(isqrt(&n), Ok(biguint!(9)));
    }

    #[test]
    fn calculate_isqrt_b() {
        let n = biguint_str!("4573659632505831259480");
        assert_eq!(isqrt(&n.pow(2_u32)), Ok(n));
    }

    #[test]
    fn calculate_isqrt_c() {
        let n = biguint_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481"
        );
        assert_eq!(isqrt(&n.pow(2_u32)), Ok(n));
    }

    #[test]
    fn calculate_isqrt_zero() {
        let n = BigUint::zero();
        assert_eq!(isqrt(&n), Ok(BigUint::zero()));
    }
}

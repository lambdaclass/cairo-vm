use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use std::{
    convert::Into,
    fmt,
    ops::{
        Add, /*SubAssign,*/ Div, /*DivAssign*/
        /*AddAssign,*/ Mul, Shr, /*MulAssign,*/ Sub,
    },
};

pub type Felt = FeltBigInt;

pub const PRIME_STR: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
pub const FIELD: (u128, u128) = ((1 << 123) + (17 << 64), 1);

lazy_static! {
    pub static ref CAIRO_PRIME: BigInt =
        (Into::<BigInt>::into(FIELD.0) << 128) + Into::<BigInt>::into(FIELD.1);
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Clone, Debug)]
pub struct FeltBigInt(BigInt);

impl FeltBigInt {
    pub fn new<T: Into<BigInt>>(value: T) -> Self {
        FeltBigInt(Into::<BigInt>::into(value).mod_floor(&CAIRO_PRIME))
    }

    pub fn zero() -> Self {
        FeltBigInt(BigInt::zero())
    }

    pub fn one() -> Self {
        FeltBigInt(BigInt::one())
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn to_usize(&self) -> Option<usize> {
        self.0.to_usize()
    }

    pub fn to_i64(&self) -> Option<i64> {
        self.0.to_i64()
    }

    pub fn from_usize(num: usize) -> Option<Self> {
        BigInt::from_usize(num).map(FeltBigInt)
    }
}

impl Add for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FeltBigInt((self.0 + rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

/*impl AddAssign for FeltBigInt {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = (self.0 + rhs.0).mod_floor(&CAIRO_PRIME);
    }
}*/

impl Mul for FeltBigInt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FeltBigInt((self.0 * rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

/*impl MulAssign for FeltBigInt {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = (self.0 * rhs.0).mod_floor(&CAIRO_PRIME);
    }
}*/

impl Sub for FeltBigInt {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        FeltBigInt((self.0 - rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

/*impl SubAssign for FeltBigInt {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = (self.0 - rhs.0).mod_floor(&CAIRO_PRIME);
    }
}*/

impl Div for FeltBigInt {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        FeltBigInt((self.0 / rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

/*impl DivAssign for FeltBigInt {
    fn div_assign(&mut self, rhs: Self) {
        self.0 = (self.0 * rhs.0).mod_floor(&CAIRO_PRIME);
    }
}*/

impl Shr<usize> for FeltBigInt {
    type Output = Self;
    fn shr(self, other: usize) -> Self {
        FeltBigInt((self.0).shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Add for &'a FeltBigInt {
    type Output = FeltBigInt;

    fn add(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl<'a> Add<usize> for &'a FeltBigInt {
    type Output = FeltBigInt;

    fn add(self, other: usize) -> Self::Output {
        FeltBigInt(self.0 + other)
    }
}

impl fmt::Display for FeltBigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[macro_export]
macro_rules! felt_str {
    ($val: expr) => {
        Felt::new(BigInt::parse_bytes($val.as_bytes(), 10).expect("Couldn't parse bytes"))
    };
    ($val: expr, $opt: expr) => {
        Felt::new(BigInt::parse_bytes($val.as_bytes(), $opt).expect("Couldn't parse bytes"))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_felts_within_field() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(3);

        assert_eq!(a + b, c);
    }

    fn add_felts_overflow() {
        let a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(1);

        assert_eq!(a + b, c);
    }

    /*
    fn add_assign_felts_within_field() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        a += b;
        let c = FeltBigInt::new(3);

        assert_eq!(a, c);
    }

    fn add_assign_felts_overflow() {
        let a = felt_str!(
            b"800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        a += b;
        let c = FeltBigInt::new(1);

        assert_eq!(a, c);
    }*/

    fn mul_felts_within_field() {
        let a = FeltBigInt::new(2);
        let b = FeltBigInt::new(3);
        let c = FeltBigInt::new(6);

        assert_eq!(a * b, c);
    }

    fn mul_felts_overflow() {
        let a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(1);

        assert_eq!(a * b, c);
    }

    /*
    fn mul_assign_felts_within_field() {
        let a = FeltBigInt::new(2);
        let b = FeltBigInt::new(3);
        a *= b;
        let c = FeltBigInt::new(6);

        assert_eq!(a, c);
    }

    fn mul_assign_felts_overflow() {
        let a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        a *= b;
        let c = FeltBigInt::new(2);

        assert_eq!(a, c);
    }*/

    fn sub_felts_within_field() {
        let a = FeltBigInt::new(3);
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(1);

        assert_eq!(a - b, c);
    }

    fn sub_felts_overflow() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        let c = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );

        assert_eq!(a - b, c);
    }

    /*fn sub_assign_felts_within_field() {
        let a = FeltBigInt::new(3);
        let b = FeltBigInt::new(2);
        a -= b;
        let c = FeltBigInt::new(1);

        assert_eq!(a, c);
    }

    fn sub_assign_felts_overflow() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        a -= b;
        let c = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );

        assert_eq!(a, c);
    }*/
}

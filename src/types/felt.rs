use lazy_static::lazy_static;
use num_bigint::{BigInt, ParseBigIntError, Sign, U64Digits};
use num_integer::Integer;
use num_traits::{FromPrimitive, One, Signed, ToPrimitive, Zero};
use serde::Deserialize;
use std::{
    cmp::Ordering,
    convert::Into,
    fmt,
    iter::Sum,
    ops::{Add, BitAnd, Div, Mul, Rem, Shl, Shr, ShrAssign, Sub},
};

pub type Felt = FeltBigInt;

pub const PRIME_STR: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
pub const FIELD: (u128, u128) = ((1 << 123) + (17 << 64), 1);

lazy_static! {
    pub static ref CAIRO_PRIME: BigInt =
        (Into::<BigInt>::into(FIELD.0) << 128) + Into::<BigInt>::into(FIELD.1);
}

pub type ParseFeltError = ParseBigIntError;

#[derive(Eq, Hash, PartialEq, PartialOrd, Clone, Debug, Deserialize)]
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

    pub fn is_negative(&self) -> bool {
        &self.0 > &CAIRO_PRIME.shr(1)
    }

    pub fn is_positive(&self) -> bool {
        !self.is_negative() && !self.is_zero()
    }

    pub fn mod_floor(&self, other: &FeltBigInt) -> Self {
        FeltBigInt(self.0.mod_floor(&other.0))
    }

    pub fn div_floor(&self, other: &FeltBigInt) -> Self {
        FeltBigInt(self.0.div_floor(&other.0))
    }

    pub fn div_mod_floor(&self, other: &FeltBigInt) -> (Self, Self) {
        let (d, m) = self.0.div_mod_floor(&other.0);
        (FeltBigInt(d), FeltBigInt(m))
    }

    pub fn pow(&self, other: u32) -> Self {
        FeltBigInt(self.0.pow(other).mod_floor(&CAIRO_PRIME))
    }

    pub fn to_usize(&self) -> Option<usize> {
        self.0.to_usize()
    }

    pub fn to_isize(&self) -> Option<isize> {
        self.0.to_isize()
    }

    pub fn to_u32(&self) -> Option<u32> {
        self.0.to_u32()
    }

    pub fn to_i32(&self) -> Option<i32> {
        self.0.to_i32()
    }

    pub fn to_i64(&self) -> Option<i64> {
        self.0.to_i64()
    }

    pub fn to_u64(&self) -> Option<u64> {
        self.0.to_u64()
    }

    pub fn iter_u64_digits(&self) -> U64Digits {
        self.0.iter_u64_digits()
    }

    pub fn from_usize(num: usize) -> Option<Self> {
        BigInt::from_usize(num).map(FeltBigInt)
    }

    pub fn to_signed_bytes_le(&self) -> Vec<u8> {
        self.0.to_signed_bytes_le()
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.to_bytes_be().1
    }

    pub fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        BigInt::parse_bytes(buf, radix).map(FeltBigInt)
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Felt {
        FeltBigInt::new(BigInt::from_bytes_be(Sign::Plus, bytes))
    }
}

impl Add for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FeltBigInt((self.0 + rhs.0).mod_floor(&CAIRO_PRIME))
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
        FeltBigInt((self.0 + other).mod_floor(&CAIRO_PRIME))
    }
}

impl Sum for FeltBigInt {
    fn sum<I: Iterator<Item = Self>> (iter: I) -> Self {
        iter.fold(FeltBigInt::zero(), Add::add)
    }
}

impl Mul for FeltBigInt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FeltBigInt((self.0 * rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Mul for &'a FeltBigInt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self * rhs
    }
}

impl Sub for FeltBigInt {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        FeltBigInt((self.0 - rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Sub for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltBigInt((self.0 - rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl Div for FeltBigInt {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        FeltBigInt((self.0 / rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Div<FeltBigInt> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn div(self, rhs: FeltBigInt) -> Self::Output {
        self / rhs
    }
}

impl<'a> Rem<&'a FeltBigInt> for FeltBigInt {
    type Output = Self;
    fn rem(self, rhs: &'a FeltBigInt) -> Self {
        FeltBigInt(self.0 % rhs.0)
    }
}

impl Shl<usize> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: usize) -> Self {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl Shl<u32> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: u32) -> Self {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl Shr<usize> for FeltBigInt {
    type Output = Self;
    fn shr(self, other: usize) -> Self {
        FeltBigInt((self.0).shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl ShrAssign<usize> for FeltBigInt {
    fn shr_assign(&mut self, other: usize) {
        self.0 = self.0.shr(other).mod_floor(&CAIRO_PRIME);
    }
}

impl<'a> Shr<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt((self.0).shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> BitAnd<&'a FeltBigInt> for FeltBigInt {
    type Output = Self;
    fn bitand(self, rhs: &'a FeltBigInt) -> Self {
        FeltBigInt(self.0 & rhs.0)
    }
}

impl<'a> BitAnd<FeltBigInt> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        FeltBigInt(self.0 & rhs.0)
    }
}

pub fn div_rem(x: &FeltBigInt, y: &FeltBigInt) -> (FeltBigInt, FeltBigInt) {
    let (d, m) = x.0.div_mod_floor(&y.0);
    (FeltBigInt(d), FeltBigInt(m))
}

impl Ord for FeltBigInt {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.0.cmp(&rhs.0)
    }
}

impl fmt::Display for FeltBigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[macro_use]
pub mod felt_test_utils {
    use super::*;

    impl FeltBigInt {
        pub fn new_str(num: &str, base: u8) -> Self {
            Felt::new(BigInt::parse_bytes(num.as_bytes(), base).expect("Couldn't parse bytes"))
        }
    }

    #[macro_export]
    macro_rules! felt_str {
        ($val: expr) => {
            Felt::new_str($val, 10)
        };
        ($val: expr, $opt: expr) => {
            Felt::new_str($val, $opt)
        };
    }
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

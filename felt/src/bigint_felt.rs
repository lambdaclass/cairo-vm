use lazy_static::lazy_static;
use num_bigint::{BigInt, ParseBigIntError, Sign, U64Digits};
use num_integer::Integer;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use serde::Deserialize;
use std::{
    cmp::Ordering,
    convert::Into,
    fmt,
    iter::Sum,
    ops::{Add, AddAssign, BitAnd, Div, Mul, MulAssign, Rem, Shl, Shr, ShrAssign, Sub, SubAssign},
};

use crate::FIELD;

lazy_static! {
    pub static ref CAIRO_PRIME: BigInt =
        (Into::<BigInt>::into(FIELD.0) << 128) + Into::<BigInt>::into(FIELD.1);
    static ref SIGNED_FELT_MAX: BigInt = CAIRO_PRIME.clone().shr(1);
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
        &self.0 > &SIGNED_FELT_MAX
    }

    pub fn is_positive(&self) -> bool {
        !self.is_zero() && !self.is_negative()
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

    /// Naive mul inverse using Fermats little theorem
    /// a^(m - 1) mod m = 1 if m prime
    /// a^(m - 2) mod m = a^(-1)
    pub fn mul_inverse(&self) -> Self {
        let mut exponent = FeltBigInt::zero() - FeltBigInt::new(2);
        let mut res = FeltBigInt::one();
        while !exponent.is_zero() {
            res *= self;
            exponent = exponent - FeltBigInt::one();
        }
        res
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

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self::new(BigInt::from_bytes_be(Sign::Plus, bytes))
    }

    pub fn to_str_radix(&self, radix: u32) -> String {
        self.0.to_str_radix(radix)
    }
}

impl Add for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut sum = self.0 + rhs.0;
        if sum >= *CAIRO_PRIME {
            sum -= CAIRO_PRIME.clone();
        }
        FeltBigInt(sum)
    }
}

impl<'a> Add for &'a FeltBigInt {
    type Output = FeltBigInt;

    fn add(self, rhs: Self) -> Self::Output {
        self.clone() + rhs.clone()
    }
}

impl<T: Into<BigInt>> Add<T> for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: T) -> Self::Output {
        let mut sum = self.0 + rhs.into();
        if sum >= *CAIRO_PRIME {
            sum -= CAIRO_PRIME.clone();
        }
        FeltBigInt(sum)
    }
}

impl<'a, T: Into<BigInt>> Add<T> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn add(self, rhs: T) -> Self::Output {
        self.clone() + rhs.into()
    }
}

impl AddAssign for FeltBigInt {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl Sum for FeltBigInt {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(FeltBigInt::zero(), Add::add)
    }
}

impl Mul for FeltBigInt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        FeltBigInt((self.0 * rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Mul for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn mul(self, rhs: Self) -> Self::Output {
        self.clone() * rhs.clone()
    }
}

impl<'a> MulAssign<&'a FeltBigInt> for FeltBigInt {
    fn mul_assign(&mut self, rhs: &'a FeltBigInt) {
        self.0 = (self.0.clone() * rhs.0.clone()).mod_floor(&CAIRO_PRIME);
    }
}

impl Sub for FeltBigInt {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltBigInt((self.0 - rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Sub for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltBigInt((self.0.clone() - rhs.0.clone()).mod_floor(&CAIRO_PRIME))
    }
}

impl Sub<FeltBigInt> for usize {
    type Output = FeltBigInt;

    fn sub(self, rhs: FeltBigInt) -> Self::Output {
        FeltBigInt((BigInt::from(self) - rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl Sub<&FeltBigInt> for usize {
    type Output = FeltBigInt;

    fn sub(self, rhs: &FeltBigInt) -> Self::Output {
        self - rhs.clone()
    }
}

impl SubAssign for FeltBigInt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl Div for FeltBigInt {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        FeltBigInt((self.0 / rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Div<FeltBigInt> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn div(self, rhs: FeltBigInt) -> Self::Output {
        self.clone() / rhs.clone()
    }
}

impl<'a> Rem<&'a FeltBigInt> for FeltBigInt {
    type Output = Self;
    fn rem(self, rhs: &'a FeltBigInt) -> Self::Output {
        FeltBigInt(self.0.clone() % rhs.0.clone())
    }
}

impl Shl<usize> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl Shl<u32> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl Shr<usize> for FeltBigInt {
    type Output = Self;
    fn shr(self, other: usize) -> Self::Output {
        FeltBigInt((self.0).shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl ShrAssign<usize> for FeltBigInt {
    fn shr_assign(&mut self, other: usize) {
        self.0 = self.0.clone().shr(other).mod_floor(&CAIRO_PRIME);
    }
}

impl<'a> Shr<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt(self.0.clone().shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> BitAnd<&'a FeltBigInt> for FeltBigInt {
    type Output = Self;
    fn bitand(self, rhs: &'a FeltBigInt) -> Self::Output {
        FeltBigInt(self.0 & rhs.0.clone())
    }
}

impl<'a> BitAnd<FeltBigInt> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        FeltBigInt(self.0.clone() & rhs.0)
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
            crate::Felt::new(
                BigInt::parse_bytes(num.as_bytes(), base as u32).expect("Couldn't parse bytes"),
            )
        }
    }

    #[macro_export]
    macro_rules! felt_str {
        ($val: expr) => {
            crate::Felt::new_str($val, 10)
        };
        ($val: expr, $opt: expr) => {
            crate::Felt::new_str($val, $opt)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_felts_within_field() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(3);

        assert_eq!(a + b, c);
    }

    #[test]
    fn add_felts_overflow() {
        let a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(1);

        assert_eq!(a + b, c);
    }

    #[test]
    fn add_assign_felts_within_field() {
        let mut a = FeltBigInt::new(1i32);
        let b = FeltBigInt::new(2i32);
        a += b;
        let c = FeltBigInt::new(3i32);

        assert_eq!(a, c);
    }

    #[test]
    fn add_assign_felts_overflow() {
        let mut a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        a += b;
        let c = FeltBigInt::new(1);

        assert_eq!(a, c);
    }

    #[test]
    fn mul_felts_within_field() {
        let a = FeltBigInt::new(2);
        let b = FeltBigInt::new(3);
        let c = FeltBigInt::new(6);

        assert_eq!(a * b, c);
    }

    #[test]
    fn mul_felts_overflow() {
        let a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        let c = felt_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020479"
        );

        assert_eq!(a * b, c);
    }

    #[test]
    fn mul_assign_felts_within_field() {
        let mut a = FeltBigInt::new(2i32);
        let b = FeltBigInt::new(3i32);
        a *= &b;
        let c = FeltBigInt::new(6i32);

        assert_eq!(a, c);
    }

    #[test]
    fn mul_assign_felts_overflow() {
        let mut a = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );
        let b = FeltBigInt::new(2);
        a *= &b;
        let c = felt_str!(
            "3618502788666131213697322783095070105623107215331596699973092056135872020479"
        );

        assert_eq!(a, c);
    }

    #[test]
    fn sub_felts_within_field() {
        let a = FeltBigInt::new(3);
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(1);

        assert_eq!(a - b, c);
    }

    #[test]
    fn sub_felts_overflow() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        let c = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );

        assert_eq!(a - b, c);
    }

    #[test]
    fn sub_assign_felts_within_field() {
        let mut a = FeltBigInt::new(3i32);
        let b = FeltBigInt::new(2i32);
        a -= b;
        let c = FeltBigInt::new(1i32);

        assert_eq!(a, c);
    }

    #[test]
    fn sub_assign_felts_overflow() {
        let mut a = FeltBigInt::new(1i32);
        let b = FeltBigInt::new(2i32);
        a -= b;
        let c = felt_str!(
            "800000000000011000000000000000000000000000000000000000000000000",
            16
        );

        assert_eq!(a, c);
    }

    #[test]
    fn sub_usize_felt() {
        let a = FeltBigInt::new(4);
        let b = FeltBigInt::new(2);

        assert_eq!(6usize - &a, b);
        assert_eq!(6usize - a, b);
    }
}

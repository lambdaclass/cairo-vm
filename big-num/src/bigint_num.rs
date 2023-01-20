use num_bigint::{BigInt, BigUint, ParseBigIntError, U64Digits};
use num_integer::Integer;
use num_traits::{FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use std::{
    convert::Into,
    fmt,
    iter::Sum,
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Div, Mul, MulAssign, Neg, Rem, Shl, Shr, ShrAssign,
        Sub, SubAssign,
    },
};

use crate::BigNumOps;

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default, Serialize)]
pub struct BigIntNum(BigInt);

macro_rules! from_integer {
    ($type:ty) => {
        impl From<$type> for BigIntNum {
            fn from(value: $type) -> Self {
                Self(value.into())
            }
        }
    };
}

macro_rules! from_unsigned {
    ($type:ty) => {
        impl From<$type> for BigIntNum {
            fn from(value: $type) -> Self {
                Self(value.into())
            }
        }
    };
}

from_integer!(i8);
from_integer!(i16);
from_integer!(i32);
from_integer!(i64);
from_integer!(i128);
from_integer!(isize);

from_unsigned!(u8);
from_unsigned!(u16);
from_unsigned!(u32);
from_unsigned!(u64);
from_unsigned!(u128);
from_unsigned!(usize);

impl From<BigUint> for BigIntNum {
    fn from(value: BigUint) -> Self {
        Self(value.into())
    }
}

impl From<&BigUint> for BigIntNum {
    fn from(value: &BigUint) -> Self {
        Self(value.clone().into())
    }
}

impl From<BigInt> for BigIntNum {
    fn from(value: BigInt) -> Self {
        Self(value)
    }
}

impl From<&BigInt> for BigIntNum {
    fn from(value: &BigInt) -> Self {
        Self(value.clone())
    }
}

impl BigNumOps for BigIntNum {
    fn modpow(&self, exponent: &BigIntNum, modulus: &BigIntNum) -> Self {
        BigIntNum(self.0.modpow(&exponent.0, &modulus.0))
    }

    fn iter_u64_digits(&self) -> U64Digits {
        self.0.iter_u64_digits()
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        self.0.to_bytes_le().1
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.0.to_bytes_be().1
    }

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        BigInt::parse_bytes(buf, radix).map(BigIntNum::new)
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        Self::new(BigUint::from_bytes_be(bytes))
    }

    fn to_str_radix(&self, radix: u32) -> String {
        self.0.to_str_radix(radix)
    }

    fn to_bigint(&self) -> BigInt {
        self.0.clone()
    }

    fn to_biguint(&self) -> Option<BigUint> {
        self.0.to_biguint()
    }

    fn sqrt(&self) -> Self {
        BigIntNum(self.0.sqrt())
    }

    fn bits(&self) -> u64 {
        self.0.bits()
    }

    fn new<T: Into<crate::BigNum>>(value: T) -> Self {
        value.into()
    }
}

impl Add for BigIntNum {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.0 += rhs.0;
        self
    }
}

impl<'a> Add for &'a BigIntNum {
    type Output = BigIntNum;

    fn add(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 + &rhs.0)
    }
}

impl<'a> Add<&'a BigIntNum> for BigIntNum {
    type Output = BigIntNum;

    fn add(mut self, rhs: &'a BigIntNum) -> Self::Output {
        self += rhs;
        self
    }
}

impl Add<u32> for BigIntNum {
    type Output = Self;
    fn add(mut self, rhs: u32) -> Self {
        self.0 += rhs;
        self
    }
}

impl Add<usize> for BigIntNum {
    type Output = Self;
    fn add(mut self, rhs: usize) -> Self {
        self.0 += rhs;
        self
    }
}

impl<'a> Add<usize> for &'a BigIntNum {
    type Output = BigIntNum;
    fn add(self, rhs: usize) -> Self::Output {
        BigIntNum(&self.0 + rhs)
    }
}

impl AddAssign for BigIntNum {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'a> AddAssign<&'a BigIntNum> for BigIntNum {
    fn add_assign(&mut self, rhs: &'a BigIntNum) {
        *self = &*self + rhs;
    }
}

impl Sum for BigIntNum {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(BigIntNum::zero(), |mut acc, x| {
            acc += x;
            acc
        })
    }
}

impl Neg for BigIntNum {
    type Output = BigIntNum;
    fn neg(self) -> Self::Output {
        if self.0.is_positive() {
            BigIntNum(-self.0)
        } else {
            self
        }
    }
}

impl<'a> Neg for &'a BigIntNum {
    type Output = BigIntNum;
    fn neg(self) -> Self::Output {
        if self.0.is_positive() {
            BigIntNum(-self.0.clone())
        } else {
            self.clone()
        }
    }
}

impl Sub for BigIntNum {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl<'a> Sub<&'a BigIntNum> for BigIntNum {
    type Output = BigIntNum;
    fn sub(mut self, rhs: &'a BigIntNum) -> Self::Output {
        self.0 -= &rhs.0;
        self
    }
}

impl<'a> Sub for &'a BigIntNum {
    type Output = BigIntNum;
    fn sub(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 - &rhs.0)
    }
}

impl Sub<u32> for BigIntNum {
    type Output = BigIntNum;
    fn sub(self, rhs: u32) -> Self {
        BigIntNum(&self.0 - rhs)
    }
}

impl<'a> Sub<u32> for &'a BigIntNum {
    type Output = BigIntNum;
    fn sub(self, rhs: u32) -> Self::Output {
        BigIntNum(&self.0 - rhs)
    }
}

impl Sub<usize> for BigIntNum {
    type Output = BigIntNum;
    fn sub(self, rhs: usize) -> Self {
        BigIntNum(&self.0 - rhs)
    }
}

impl SubAssign for BigIntNum {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'a> SubAssign<&'a BigIntNum> for BigIntNum {
    fn sub_assign(&mut self, rhs: &'a BigIntNum) {
        *self = &*self - rhs;
    }
}

impl Sub<BigIntNum> for usize {
    type Output = BigIntNum;
    fn sub(self, rhs: BigIntNum) -> Self::Output {
        self - &rhs
    }
}

impl Sub<&BigIntNum> for usize {
    type Output = BigIntNum;
    fn sub(self, rhs: &BigIntNum) -> Self::Output {
        BigIntNum(self - &rhs.0)
    }
}

impl Mul for BigIntNum {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        BigIntNum(self.0 * rhs.0)
    }
}

impl<'a> Mul for &'a BigIntNum {
    type Output = BigIntNum;
    fn mul(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 * &rhs.0)
    }
}

impl Mul<&BigIntNum> for i32 {
    type Output = BigIntNum;
    fn mul(self, rhs: &BigIntNum) -> Self::Output {
        BigIntNum(self * &rhs.0)
    }
}

impl<'a> Mul<&'a BigIntNum> for BigIntNum {
    type Output = BigIntNum;
    fn mul(self, rhs: &'a BigIntNum) -> Self::Output {
        BigIntNum(&self.0 * &rhs.0)
    }
}

impl<'a> MulAssign<&'a BigIntNum> for BigIntNum {
    fn mul_assign(&mut self, rhs: &'a BigIntNum) {
        *self = &*self * rhs;
    }
}

impl Pow<u32> for BigIntNum {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        BigIntNum(self.0.pow(rhs))
    }
}

impl<'a> Pow<u32> for &'a BigIntNum {
    type Output = BigIntNum;
    #[allow(clippy::needless_borrow)] // the borrow of self.0 is necessary becase it's of the type BigUInt, which doesn't implement the Copy trait
    fn pow(self, rhs: u32) -> Self::Output {
        BigIntNum((&self.0).pow(rhs))
    }
}

impl Div for BigIntNum {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        Self(self.0 / rhs.0)
    }
}

impl<'a> Div for &'a BigIntNum {
    type Output = BigIntNum;
    fn div(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 / &rhs.0)
    }
}

impl<'a> Div<BigIntNum> for &'a BigIntNum {
    type Output = BigIntNum;
    fn div(self, rhs: BigIntNum) -> Self::Output {
        self / &rhs
    }
}

impl Rem for BigIntNum {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        BigIntNum(self.0 % rhs.0)
    }
}

impl<'a> Rem<&'a BigIntNum> for BigIntNum {
    type Output = Self;
    fn rem(self, rhs: &'a BigIntNum) -> Self::Output {
        BigIntNum(self.0 % &rhs.0)
    }
}

impl Zero for BigIntNum {
    fn zero() -> Self {
        Self(BigInt::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for BigIntNum {
    fn one() -> Self {
        Self(BigInt::one())
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self.0.is_one()
    }
}

impl Num for BigIntNum {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        BigInt::from_str_radix(string, radix).map(BigIntNum::new)
    }
}

impl Integer for BigIntNum {
    fn div_floor(&self, other: &Self) -> Self {
        BigIntNum(self.0.div_floor(&other.0))
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        div_rem(self, other)
    }

    fn divides(&self, other: &Self) -> bool {
        self.0.divides(&other.0)
    }

    fn gcd(&self, other: &Self) -> Self {
        Self(self.0.gcd(&other.0))
    }

    fn is_even(&self) -> bool {
        self.0.is_even()
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        self.0.is_multiple_of(&other.0)
    }

    fn is_odd(&self) -> bool {
        self.0.is_odd()
    }

    fn lcm(&self, other: &Self) -> Self {
        Self::new(self.0.lcm(&other.0))
    }

    fn mod_floor(&self, other: &Self) -> Self {
        Self(self.0.mod_floor(&other.0))
    }
}

impl Signed for BigIntNum {
    fn abs(&self) -> Self {
        Self(self.0.abs())
    }

    fn abs_sub(&self, other: &Self) -> Self {
        if self > other {
            self - other
        } else {
            other - self
        }
    }

    fn signum(&self) -> Self {
        if self.is_zero() {
            BigIntNum::zero()
        } else if self.is_positive() {
            BigIntNum::one()
        } else {
            BigIntNum::new(-1)
        }
    }

    fn is_positive(&self) -> bool {
        self.0.is_positive()
    }

    fn is_negative(&self) -> bool {
        !(self.is_positive() || self.is_zero())
    }
}

impl Shl<u32> for BigIntNum {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        BigIntNum((&self.0).shl(other))
    }
}

impl<'a> Shl<u32> for &'a BigIntNum {
    type Output = BigIntNum;
    fn shl(self, other: u32) -> Self::Output {
        BigIntNum((&self.0).shl(other))
    }
}

impl Shl<usize> for BigIntNum {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        BigIntNum((&self.0).shl(other))
    }
}

impl<'a> Shl<usize> for &'a BigIntNum {
    type Output = BigIntNum;
    fn shl(self, other: usize) -> Self::Output {
        BigIntNum((&self.0).shl(other))
    }
}

impl Shr<u32> for BigIntNum {
    type Output = Self;
    fn shr(self, other: u32) -> Self::Output {
        BigIntNum(self.0.shr(other))
    }
}

impl<'a> Shr<u32> for &'a BigIntNum {
    type Output = BigIntNum;
    fn shr(self, other: u32) -> Self::Output {
        BigIntNum((&self.0).shr(other))
    }
}

impl ShrAssign<usize> for BigIntNum {
    fn shr_assign(&mut self, other: usize) {
        self.0 = (&self.0).shr(other);
    }
}

impl<'a> BitAnd for &'a BigIntNum {
    type Output = BigIntNum;
    fn bitand(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 & &rhs.0)
    }
}

impl<'a> BitAnd<&'a BigIntNum> for BigIntNum {
    type Output = Self;
    fn bitand(self, rhs: &'a BigIntNum) -> Self::Output {
        BigIntNum(self.0 & &rhs.0)
    }
}

impl<'a> BitAnd<BigIntNum> for &'a BigIntNum {
    type Output = BigIntNum;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        BigIntNum(&self.0 & rhs.0)
    }
}

impl<'a> BitOr for &'a BigIntNum {
    type Output = BigIntNum;
    fn bitor(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 | &rhs.0)
    }
}

impl<'a> BitXor for &'a BigIntNum {
    type Output = BigIntNum;
    fn bitxor(self, rhs: Self) -> Self::Output {
        BigIntNum(&self.0 ^ &rhs.0)
    }
}

pub fn div_rem(x: &BigIntNum, y: &BigIntNum) -> (BigIntNum, BigIntNum) {
    let (d, m) = x.0.div_mod_floor(&y.0);
    (BigIntNum(d), BigIntNum(m))
}

impl ToPrimitive for BigIntNum {
    fn to_u64(&self) -> Option<u64> {
        self.0.to_u64()
    }

    fn to_i64(&self) -> Option<i64> {
        self.0.to_i64()
    }

    fn to_usize(&self) -> Option<usize> {
        self.0.to_usize()
    }
}

impl FromPrimitive for BigIntNum {
    fn from_u64(n: u64) -> Option<Self> {
        BigInt::from_u64(n).map(Self)
    }

    fn from_i64(n: i64) -> Option<Self> {
        BigInt::from_i64(n).map(Self)
    }

    fn from_usize(n: usize) -> Option<Self> {
        BigInt::from_usize(n).map(Self)
    }
}

impl fmt::Display for BigIntNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for BigIntNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[macro_export]
macro_rules! felt_str {
    ($val: expr) => {
        <felt::Felt as felt::NewFelt>::new(
            num_bigint::BigInt::parse_bytes($val.as_bytes(), 10_u32).expect("Couldn't parse bytes"),
        )
    };
    ($val: expr, $opt: expr) => {
        <felt::Felt as felt::NewFelt>::new(
            num_bigint::BigInt::parse_bytes($val.as_bytes(), $opt as u32)
                .expect("Couldn't parse bytes"),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_nums() {
        let a = BigIntNum::new(1);
        let b = BigIntNum::new(2);
        let c = BigIntNum::new(3);

        assert_eq!(a + b, c);
    }

    #[test]
    fn add_assign_nums() {
        let mut a = BigIntNum::new(1i32);
        let b = BigIntNum::new(2i32);
        a += b;
        let c = BigIntNum::new(3i32);

        assert_eq!(a, c);
    }

    #[test]
    fn mul_nums() {
        let a = BigIntNum::new(2);
        let b = BigIntNum::new(3);
        let c = BigIntNum::new(6);

        assert_eq!(a * b, c);
    }

    #[test]
    fn mul_assign_nums() {
        let mut a = BigIntNum::new(2i32);
        let b = BigIntNum::new(3i32);
        a *= &b;
        let c = BigIntNum::new(6i32);

        assert_eq!(a, c);
    }

    #[test]
    fn sub_nums() {
        let a = BigIntNum::new(3);
        let b = BigIntNum::new(2);
        let c = BigIntNum::new(1);

        assert_eq!(a - b, c);
    }

    #[test]
    fn sub_assign_nums() {
        let mut a = BigIntNum::new(3i32);
        let b = BigIntNum::new(2i32);
        a -= b;
        let c = BigIntNum::new(1i32);

        assert_eq!(a, c);
    }

    #[test]
    fn sub_usize_felt() {
        let a = BigIntNum::new(4u32);
        let b = BigIntNum::new(2u32);

        assert_eq!(6usize - &a, b);
        assert_eq!(6usize - a, b);
    }

    #[test]
    fn negate_num() {
        let a = BigIntNum::new(10_i32);
        assert_eq!(
            a.neg(),
            BigIntNum::from_str_radix("-10", 10).expect("Couldn't parse int")
        );

        let c = BigIntNum::from_str_radix(
            "3618502788666131213697322783095070105623107215331596699973092056135872020471",
            10,
        )
        .expect("Couldn't parse int");

        assert_eq!(
            c.neg(),
            BigIntNum::from_str_radix(
                "-3618502788666131213697322783095070105623107215331596699973092056135872020471",
                10,
            )
            .expect("Couldn't parse int")
        );
    }
}

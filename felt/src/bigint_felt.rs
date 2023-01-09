use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint, ToBigInt, U64Digits};
use num_integer::Integer;
use num_traits::{Bounded, FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use serde::Deserialize;
use std::{
    convert::Into,
    fmt,
    iter::Sum,
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Div, Mul, MulAssign, Neg, Rem, Shl, Shr, ShrAssign,
        Sub, SubAssign,
    },
};

use crate::{FeltOps, NewFelt, ParseFeltError, FIELD};

lazy_static! {
    pub static ref CAIRO_PRIME: BigUint =
        (Into::<BigUint>::into(FIELD.0) << 128) + Into::<BigUint>::into(FIELD.1);
    pub static ref SIGNED_FELT_MAX: BigUint = (&*CAIRO_PRIME).shr(1_u32);
    pub static ref CAIRO_SIGNED_PRIME: BigInt = CAIRO_PRIME
        .to_bigint()
        .expect("Conversion BigUint -> BigInt can't fail");
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default)]
pub struct FeltBigInt(BigUint);

macro_rules! from_integer {
    ($type:ty) => {
        impl From<$type> for FeltBigInt {
            fn from(value: $type) -> Self {
                Self(
                    value
                        .try_into()
                        .unwrap_or_else(|_| &*CAIRO_PRIME - (-value as u128)),
                )
            }
        }
    };
}

macro_rules! from_unsigned {
    ($type:ty) => {
        impl From<$type> for FeltBigInt {
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

impl From<BigUint> for FeltBigInt {
    fn from(value: BigUint) -> Self {
        if value > *CAIRO_PRIME {
            Self(value.mod_floor(&CAIRO_PRIME))
        } else {
            Self(value)
        }
    }
}

impl From<&BigUint> for FeltBigInt {
    fn from(value: &BigUint) -> Self {
        if value > &*CAIRO_PRIME {
            Self(value.mod_floor(&CAIRO_PRIME))
        } else {
            Self(value.clone())
        }
    }
}

/* Code used to convert from BigUint to BigInt
   impl ToBigInt for BigUint {
       #[inline]
       fn to_bigint(&self) -> Option<BigInt> {
           if self.is_zero() {
               Some(Zero::zero())
           } else {
               Some(BigInt {
                   sign: Plus,
                   data: self.clone(),
               })
           }
       }
   }
*/

impl From<BigInt> for FeltBigInt {
    fn from(value: BigInt) -> Self {
        (&value).into()
    }
}

impl From<&BigInt> for FeltBigInt {
    fn from(value: &BigInt) -> Self {
        Self(
            value
                .mod_floor(&CAIRO_SIGNED_PRIME)
                .to_biguint()
                .expect("mod_floor is always positive"),
        )
    }
}

impl NewFelt for FeltBigInt {
    fn new<T: Into<Self>>(value: T) -> Self {
        value.into()
    }
}

impl FeltOps for FeltBigInt {
    fn modpow(&self, exponent: &FeltBigInt, modulus: &FeltBigInt) -> Self {
        FeltBigInt(self.0.modpow(&exponent.0, &modulus.0))
    }

    fn iter_u64_digits(&self) -> U64Digits {
        self.0.iter_u64_digits()
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        self.0.to_bytes_le()
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        //BigUint::parse_bytes(buf, radix).map(FeltBigInt::new)
        match BigUint::parse_bytes(buf, radix) {
            Some(parsed) => Some(FeltBigInt::new(parsed)),
            None => BigInt::parse_bytes(buf, radix).map(FeltBigInt::new),
        }
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        Self::new(BigUint::from_bytes_be(bytes))
    }

    fn to_str_radix(&self, radix: u32) -> String {
        self.0.to_str_radix(radix)
    }

    fn to_bigint(&self) -> BigInt {
        if self.is_negative() {
            BigInt::from_biguint(num_bigint::Sign::Minus, &*CAIRO_PRIME - &self.0)
        } else {
            self.0.clone().into()
        }
    }

    fn to_biguint(&self) -> BigUint {
        self.0.clone()
    }

    fn sqrt(&self) -> Self {
        FeltBigInt(self.0.sqrt())
    }

    fn bits(&self) -> u64 {
        self.0.bits()
    }
}

impl Add for FeltBigInt {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.0 += rhs.0;
        if self.0 >= *CAIRO_PRIME {
            self.0 -= &*CAIRO_PRIME;
        }
        self
    }
}

impl<'a> Add for &'a FeltBigInt {
    type Output = FeltBigInt;

    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = &self.0 + &rhs.0;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt(sum)
    }
}

impl<'a> Add<&'a FeltBigInt> for FeltBigInt {
    type Output = FeltBigInt;

    fn add(mut self, rhs: &'a FeltBigInt) -> Self::Output {
        self.0 += &rhs.0;
        if self.0 >= *CAIRO_PRIME {
            self.0 -= &*CAIRO_PRIME;
        }
        self
    }
}

impl Add<u32> for FeltBigInt {
    type Output = Self;
    fn add(mut self, rhs: u32) -> Self {
        self.0 += rhs;
        if self.0 >= *CAIRO_PRIME {
            self.0 -= &*CAIRO_PRIME;
        }
        self
    }
}

impl Add<usize> for FeltBigInt {
    type Output = Self;
    fn add(mut self, rhs: usize) -> Self {
        self.0 += rhs;
        if self.0 >= *CAIRO_PRIME {
            self.0 -= &*CAIRO_PRIME;
        }
        self
    }
}

impl<'a> Add<usize> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn add(self, rhs: usize) -> Self::Output {
        let mut sum = &self.0 + rhs;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt(sum)
    }
}

impl AddAssign for FeltBigInt {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'a> AddAssign<&'a FeltBigInt> for FeltBigInt {
    fn add_assign(&mut self, rhs: &'a FeltBigInt) {
        *self = &*self + rhs;
    }
}

impl Sum for FeltBigInt {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(FeltBigInt::zero(), |mut acc, x| {
            acc += x;
            acc
        })
    }
}

impl Neg for FeltBigInt {
    type Output = FeltBigInt;
    fn neg(self) -> Self::Output {
        FeltBigInt(&*CAIRO_PRIME - self.0)
    }
}

impl<'a> Neg for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn neg(self) -> Self::Output {
        FeltBigInt(&*CAIRO_PRIME - &self.0)
    }
}

impl Sub for FeltBigInt {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        if self.0 < rhs.0 {
            self.0 += &*CAIRO_PRIME;
        }
        self.0 -= rhs.0;
        self
    }
}

impl<'a> Sub<&'a FeltBigInt> for FeltBigInt {
    type Output = FeltBigInt;
    fn sub(mut self, rhs: &'a FeltBigInt) -> Self::Output {
        if self.0 < rhs.0 {
            self.0 += &*CAIRO_PRIME;
        }
        self.0 -= &rhs.0;
        self
    }
}

impl<'a> Sub for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltBigInt(if self.0 < rhs.0 {
            &*CAIRO_PRIME - (&rhs.0 - &self.0)
        } else {
            &self.0 - &rhs.0
        })
    }
}

impl Sub<u32> for FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: u32) -> Self {
        match (&self.0).to_u32() {
            Some(num) if num < rhs => Self(&*CAIRO_PRIME - (rhs - self.0)),
            _ => Self(self.0 - rhs),
        }
    }
}

impl<'a> Sub<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: u32) -> Self::Output {
        match (&self.0).to_u32() {
            Some(num) if num < rhs => FeltBigInt(&*CAIRO_PRIME - (rhs - &self.0)),
            _ => FeltBigInt(&self.0 - rhs),
        }
    }
}

impl Sub<usize> for FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: usize) -> Self {
        match (&self.0).to_usize() {
            Some(num) if num < rhs => FeltBigInt(&*CAIRO_PRIME - (rhs - num)),
            _ => FeltBigInt(self.0 - rhs),
        }
    }
}

impl SubAssign for FeltBigInt {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'a> SubAssign<&'a FeltBigInt> for FeltBigInt {
    fn sub_assign(&mut self, rhs: &'a FeltBigInt) {
        *self = &*self - rhs;
    }
}

impl Sub<FeltBigInt> for usize {
    type Output = FeltBigInt;
    fn sub(self, rhs: FeltBigInt) -> Self::Output {
        self - &rhs
    }
}

impl Sub<&FeltBigInt> for usize {
    type Output = FeltBigInt;
    fn sub(self, rhs: &FeltBigInt) -> Self::Output {
        match (&rhs.0).to_usize() {
            Some(num) => {
                if num > self {
                    FeltBigInt(&*CAIRO_PRIME - (num - self))
                } else {
                    FeltBigInt::new(self - num)
                }
            }
            None => FeltBigInt(&*CAIRO_PRIME - (&rhs.0 - self)),
        }
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
        FeltBigInt((&self.0 * &rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Mul<&'a FeltBigInt> for FeltBigInt {
    type Output = FeltBigInt;
    fn mul(self, rhs: &'a FeltBigInt) -> Self::Output {
        FeltBigInt((&self.0 * &rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> MulAssign<&'a FeltBigInt> for FeltBigInt {
    fn mul_assign(&mut self, rhs: &'a FeltBigInt) {
        *self = &*self * rhs;
    }
}

impl Pow<u32> for FeltBigInt {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        FeltBigInt(self.0.pow(rhs).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Pow<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn pow(self, rhs: u32) -> Self::Output {
        FeltBigInt((&self.0).pow(rhs).mod_floor(&CAIRO_PRIME))
    }
}

impl Div for FeltBigInt {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        FeltBigInt(self.0 / rhs.0)
    }
}

impl<'a> Div for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn div(self, rhs: Self) -> Self::Output {
        FeltBigInt(&self.0 / &rhs.0)
    }
}

impl<'a> Div<FeltBigInt> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn div(self, rhs: FeltBigInt) -> Self::Output {
        FeltBigInt(&self.0 / rhs.0)
    }
}

impl Rem for FeltBigInt {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        FeltBigInt(self.0 % rhs.0)
    }
}

impl<'a> Rem<&'a FeltBigInt> for FeltBigInt {
    type Output = Self;
    fn rem(self, rhs: &'a FeltBigInt) -> Self::Output {
        FeltBigInt(self.0 % &rhs.0)
    }
}

impl Zero for FeltBigInt {
    fn zero() -> Self {
        Self(BigUint::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for FeltBigInt {
    fn one() -> Self {
        Self(BigUint::one())
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self.0.is_one()
    }
}

impl Bounded for FeltBigInt {
    fn min_value() -> Self {
        Self::zero()
    }
    fn max_value() -> Self {
        Self(&*CAIRO_PRIME - 1_u32)
    }
}

impl Num for FeltBigInt {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match BigUint::from_str_radix(string, radix) {
            Ok(num) => Ok(FeltBigInt::new(num)),
            Err(_) => Err(ParseFeltError),
        }
    }
}

impl Integer for FeltBigInt {
    fn div_floor(&self, other: &Self) -> Self {
        FeltBigInt(self.0.div_floor(&other.0))
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

impl Signed for FeltBigInt {
    fn abs(&self) -> Self {
        if self.is_negative() {
            self.neg()
        } else {
            self.clone()
        }
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
            FeltBigInt::zero()
        } else if self.is_positive() {
            FeltBigInt::one()
        } else {
            FeltBigInt::max_value()
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && self.0 < *SIGNED_FELT_MAX
    }

    fn is_negative(&self) -> bool {
        !(self.is_positive() || self.is_zero())
    }
}

impl Shl<u32> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Shl<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt((&self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl Shl<usize> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Shl<usize> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shl(self, other: usize) -> Self::Output {
        FeltBigInt((&self.0).shl(other).mod_floor(&CAIRO_PRIME))
    }
}

impl Shr<u32> for FeltBigInt {
    type Output = Self;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt(self.0.shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Shr<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt((&self.0).shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl ShrAssign<usize> for FeltBigInt {
    fn shr_assign(&mut self, other: usize) {
        self.0 = (&self.0).shr(other).mod_floor(&CAIRO_PRIME);
    }
}

impl<'a> BitAnd for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn bitand(self, rhs: Self) -> Self::Output {
        FeltBigInt(&self.0 & &rhs.0)
    }
}

impl<'a> BitAnd<&'a FeltBigInt> for FeltBigInt {
    type Output = Self;
    fn bitand(self, rhs: &'a FeltBigInt) -> Self::Output {
        FeltBigInt(self.0 & &rhs.0)
    }
}

impl<'a> BitAnd<FeltBigInt> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        FeltBigInt(&self.0 & rhs.0)
    }
}

impl<'a> BitOr for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn bitor(self, rhs: Self) -> Self::Output {
        FeltBigInt(&self.0 | &rhs.0)
    }
}

impl<'a> BitXor for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn bitxor(self, rhs: Self) -> Self::Output {
        FeltBigInt(&self.0 ^ &rhs.0)
    }
}

pub fn div_rem(x: &FeltBigInt, y: &FeltBigInt) -> (FeltBigInt, FeltBigInt) {
    let (d, m) = x.0.div_mod_floor(&y.0);
    (FeltBigInt(d), FeltBigInt(m))
}

impl ToPrimitive for FeltBigInt {
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

impl FromPrimitive for FeltBigInt {
    fn from_u64(n: u64) -> Option<Self> {
        BigUint::from_u64(n).map(Self)
    }

    fn from_i64(n: i64) -> Option<Self> {
        BigUint::from_i64(n).map(Self)
    }

    fn from_usize(n: usize) -> Option<Self> {
        BigUint::from_usize(n).map(Self)
    }
}

impl fmt::Display for FeltBigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for FeltBigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ParseFeltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", ParseFeltError)
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
    fn add_felts_within_field() {
        let a = FeltBigInt::new(1);
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(3);

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
    fn mul_felts_within_field() {
        let a = FeltBigInt::new(2);
        let b = FeltBigInt::new(3);
        let c = FeltBigInt::new(6);

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
    fn sub_felts_within_field() {
        let a = FeltBigInt::new(3);
        let b = FeltBigInt::new(2);
        let c = FeltBigInt::new(1);

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
    fn sub_usize_felt() {
        let a = FeltBigInt::new(4u32);
        let b = FeltBigInt::new(2u32);

        assert_eq!(6usize - &a, b);
        assert_eq!(6usize - a, b);
    }

    #[test]
    fn negate_num() {
        let a = FeltBigInt::new(10_i32);
        let b = a.neg();
        assert_eq!(
            b,
            FeltBigInt::from_str_radix(
                "3618502788666131213697322783095070105623107215331596699973092056135872020471",
                10
            )
            .expect("Couldn't parse int")
        );

        let c = FeltBigInt::from_str_radix(
            "3618502788666131213697322783095070105623107215331596699973092056135872020471",
            10,
        )
        .expect("Couldn't parse int");
        let d = c.neg();
        assert_eq!(d, FeltBigInt::new(10_i32));
    }
}

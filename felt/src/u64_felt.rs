use num_bigint::{BigInt, BigUint, ToBigUint, U64Digits};
use num_integer::Integer;
use num_traits::{Bounded, FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
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

use crate::{FeltOps, ParseFeltError};

pub const OXFOI_PRIME: u64 = 18446744069414584321;

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default, Serialize)]
pub(crate) struct FeltU64 {
    val: u64,
}

macro_rules! from_integer {
    ($type:ty) => {
        impl From<$type> for FeltU64 {
            fn from(value: $type) -> Self {
                Self {
                    val: value
                        .try_into()
                        .unwrap_or_else(|_| value.mod_floor(OXFOI_PRIME)),
                }
            }
        }
    };
}

macro_rules! from_unsigned {
    ($type:ty) => {
        impl From<$type> for FeltU64 {
            fn from(value: $type) -> Self {
                Self { val: value.into() }
            }
        }
    };
}

from_integer!(i8);
from_integer!(i16);
from_integer!(i32);
from_integer!(i64);

from_unsigned!(u8);
from_unsigned!(u16);
from_unsigned!(u32);
from_unsigned!(u64);

impl From<BigUint> for FeltU64 {
    fn from(value: BigUint) -> Self {
        Self {
            val: value
                .mod_floor(&BigUint::from(OXFOI_PRIME))
                .to_u64()
                .unwrap(),
        }
    }
}

impl From<&BigUint> for FeltU64 {
    fn from(value: &BigUint) -> Self {
        Self {
            val: value
                .mod_floor(&BigUint::from(OXFOI_PRIME))
                .to_u64()
                .unwrap(),
        }
    }
}

impl From<BigInt> for FeltU64 {
    fn from(value: BigInt) -> Self {
        (&value).into()
    }
}

impl From<&BigInt> for FeltU64 {
    fn from(value: &BigInt) -> Self {
        Self {
            val: value
                .mod_floor(&BigInt::from(OXFOI_PRIME))
                .to_u64()
                .unwrap(),
        }
    }
}

impl FeltOps for FeltU64 {
    fn new<T: Into<FeltU64>>(value: T) -> FeltU64 {
        value.into()
    }

    fn modpow(&self, exponent: &FeltU64, modulus: &FeltU64) -> FeltU64 {
        FeltU64 {
            val: self.val.pow(&exponent.val).mod_floor(&modulus.val),
        }
    }

    fn iter_u64_digits(&self) -> U64Digits {
        self.val.into()
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        self.val.to_bytes_le()
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.val.to_bytes_be()
    }

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<FeltU64> {
        u64::parse_bytes(buf, radix).map(FeltU64::new)
    }

    fn from_bytes_be(bytes: &[u8]) -> FeltU64 {
        let mut value = u64::from_bytes_be(bytes);
        if value >= *OXFOI_PRIME {
            value = value.mod_floor(&OXFOI_PRIME);
        }
        Self::from(value)
    }

    fn to_str_radix(&self, radix: u32) -> String {
        self.val.to_str_radix(radix)
    }

    fn to_bigint(&self) -> BigInt {
        if self.is_negative() {
            BigInt::from_u64(-(&*OXFOI_PRIME - &self.val))
        } else {
            self.val.into()
        }
    }

    fn to_biguint(&self) -> BigUint {
        self.val.into()
    }

    fn sqrt(&self) -> FeltU64 {
        FeltU64 {
            val: self.val.sqrt(),
        }
    }

    fn bits(&self) -> u64 {
        self.val.bits()
    }

    fn prime() -> Self {
        OXFOI_PRIME
    }
}

impl Add for FeltU64 {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.val += rhs.val;
        if self.val >= *OXFOI_PRIME {
            self.val -= &*OXFOI_PRIME;
        }
        self
    }
}

impl Add for &FeltU64 {
    type Output = FeltU64;

    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = &self.val + &rhs.val;
        if sum >= *OXFOI_PRIME {
            sum -= &*OXFOI_PRIME;
        }
        FeltU64 { val: sum }
    }
}

impl Add<&FeltU64> for FeltU64 {
    type Output = FeltU64;

    fn add(mut self, rhs: &FeltU64) -> Self::Output {
        self.val += &rhs.val;
        if self.val >= *OXFOI_PRIME {
            self.val -= &*OXFOI_PRIME;
        }
        self
    }
}

impl Add<u32> for FeltU64 {
    type Output = Self;
    fn add(mut self, rhs: u32) -> Self {
        self.val += rhs;
        if self.val >= *OXFOI_PRIME {
            self.val -= &*OXFOI_PRIME;
        }
        self
    }
}

impl Add<usize> for FeltU64 {
    type Output = Self;
    fn add(mut self, rhs: usize) -> Self {
        self.val += rhs;
        if self.val >= *OXFOI_PRIME {
            self.val -= &*OXFOI_PRIME;
        }
        self
    }
}

impl Add<usize> for &FeltU64 {
    type Output = FeltU64;
    fn add(self, rhs: usize) -> Self::Output {
        let mut sum = &self.val + rhs;
        if sum >= *OXFOI_PRIME {
            sum -= &*OXFOI_PRIME;
        }
        FeltU64 { val: sum }
    }
}

impl AddAssign for FeltU64 {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl AddAssign<&FeltU64> for FeltU64 {
    fn add_assign(&mut self, rhs: &FeltU64) {
        *self = &*self + rhs;
    }
}

impl Sum for FeltU64 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(FeltU64::zero(), |mut acc, x| {
            acc += x;
            acc
        })
    }
}

impl Neg for FeltU64 {
    type Output = FeltU64;
    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self
        } else {
            FeltU64 {
                val: &*OXFOI_PRIME - self.val,
            }
        }
    }
}

impl Neg for &FeltU64 {
    type Output = FeltU64;
    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self.clone()
        } else {
            FeltU64 {
                val: &*OXFOI_PRIME - &self.val,
            }
        }
    }
}

impl Sub for FeltU64 {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        if self.val < rhs.val {
            self.val += &*OXFOI_PRIME;
        }
        self.val -= rhs.val;
        self
    }
}

impl Sub<&FeltU64> for FeltU64 {
    type Output = FeltU64;
    fn sub(mut self, rhs: &FeltU64) -> Self::Output {
        if self.val < rhs.val {
            self.val += &*OXFOI_PRIME;
        }
        self.val -= &rhs.val;
        self
    }
}

impl Sub for &FeltU64 {
    type Output = FeltU64;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltU64 {
            val: if self.val < rhs.val {
                &*OXFOI_PRIME - (&rhs.val - &self.val)
            } else {
                &self.val - &rhs.val
            },
        }
    }
}

impl Sub<u32> for FeltU64 {
    type Output = FeltU64;
    fn sub(self, rhs: u32) -> Self {
        match (self.val).to_u32() {
            Some(num) if num < rhs => Self {
                val: &*OXFOI_PRIME - (rhs - self.val),
            },
            _ => Self {
                val: self.val - rhs,
            },
        }
    }
}

impl Sub<u32> for &FeltU64 {
    type Output = FeltU64;
    fn sub(self, rhs: u32) -> Self::Output {
        match (self.val).to_u32() {
            Some(num) if num < rhs => FeltU64 {
                val: OXFOI_PRIME - (rhs - &self.val),
            },
            _ => FeltU64 {
                val: &self.val - rhs,
            },
        }
    }
}

impl Sub<usize> for FeltU64 {
    type Output = FeltU64;
    fn sub(self, rhs: usize) -> Self {
        match (self.val).to_usize() {
            Some(num) if num < rhs => FeltU64 {
                val: OXFOI_PRIME - (rhs - num),
            },
            _ => FeltU64 {
                val: self.val - rhs,
            },
        }
    }
}

impl SubAssign for FeltU64 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl SubAssign<&FeltU64> for FeltU64 {
    fn sub_assign(&mut self, rhs: &FeltU64) {
        *self = &*self - rhs;
    }
}

impl Sub<FeltU64> for usize {
    type Output = FeltU64;
    fn sub(self, rhs: FeltU64) -> Self::Output {
        self - &rhs
    }
}

impl Sub<&FeltU64> for usize {
    type Output = FeltU64;
    fn sub(self, rhs: &FeltU64) -> Self::Output {
        match self.to_u64() {
            Some(num) => {
                if num < rhs.val {
                    FeltU64 {
                        val: OXFOI_PRIME - (rhs.val - num),
                    }
                } else {
                    FeltU64::new(num - rhs.val)
                }
            }
            None => FeltU64::from(OXFOI_PRIME as usize - (rhs.val as usize - self)),
        }
    }
}

impl Mul for FeltU64 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        FeltU64 {
            val: (self.val * rhs.val).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Mul for &FeltU64 {
    type Output = FeltU64;
    fn mul(self, rhs: Self) -> Self::Output {
        FeltU64 {
            val: (&self.val * &rhs.val).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Mul<&FeltU64> for FeltU64 {
    type Output = FeltU64;
    fn mul(self, rhs: &FeltU64) -> Self::Output {
        FeltU64 {
            val: (&self.val * &rhs.val).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl MulAssign<&FeltU64> for FeltU64 {
    fn mul_assign(&mut self, rhs: &FeltU64) {
        *self = &*self * rhs;
    }
}

impl Pow<u32> for FeltU64 {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        FeltU64 {
            val: self.val.pow(rhs).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Pow<u32> for &FeltU64 {
    type Output = FeltU64;
    #[allow(clippy::needless_borrow)] // the borrow of self.val is necessary becase it's of the type BigUInt, which doesn't implement the Copy trait
    fn pow(self, rhs: u32) -> Self::Output {
        FeltU64 {
            val: (&self.val).pow(rhs).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Div for FeltU64 {
    type Output = Self;
    // In Felts `x / y` needs to be expressed as `x * y^-1`
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        if rhs.is_zero() {
            panic!("Can't divide Felt by zero")
        }

        FeltU64::new(self.val * f64::powi(rhs.val as f64, -1) as u64)
    }
}

impl Div for &FeltU64 {
    type Output = FeltU64;
    // In Felts `x / y` needs to be expressed as `x * y^-1`
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        if rhs.is_zero() {
            panic!("Can't divide Felt by zero")
        }

        FeltU64::new(self.val * f64::powi(rhs.val as f64, -1) as u64)
    }
}

impl Div<FeltU64> for &FeltU64 {
    type Output = FeltU64;
    // In Felts `x / y` needs to be expressed as `x * y^-1`
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: FeltU64) -> Self::Output {
        self / &rhs
    }
}

impl Rem for FeltU64 {
    type Output = Self;
    fn rem(self, _rhs: Self) -> Self {
        FeltU64::zero()
    }
}

impl Rem<&FeltU64> for FeltU64 {
    type Output = Self;
    fn rem(self, _rhs: &FeltU64) -> Self::Output {
        FeltU64::zero()
    }
}

impl Zero for FeltU64 {
    fn zero() -> Self {
        Self { val: u64::zero() }
    }

    fn is_zero(&self) -> bool {
        self.val.is_zero()
    }
}

impl One for FeltU64 {
    fn one() -> Self {
        Self { val: u64::one() }
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self.val.is_one()
    }
}

impl Bounded for FeltU64 {
    fn min_value() -> Self {
        Self::zero()
    }
    fn max_value() -> Self {
        Self {
            val: OXFOI_PRIME - 1_u64,
        }
    }
}

impl Num for FeltU64 {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match BigUint::from_str_radix(string, radix) {
            Ok(num) => Ok(FeltU64::new(num)),
            Err(_) => Err(ParseFeltError),
        }
    }
}

impl Integer for FeltU64 {
    fn div_floor(&self, other: &Self) -> Self {
        FeltU64 {
            val: &self.val / &other.val,
        }
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (d, m) = self.val.div_mod_floor(&other.val);
        (FeltU64 { val: d }, FeltU64 { val: m })
    }

    fn divides(&self, other: &Self) -> bool {
        self.val.is_multiple_of(&other.val)
    }

    fn gcd(&self, other: &Self) -> Self {
        Self {
            val: self.val.gcd(&other.val),
        }
    }

    fn is_even(&self) -> bool {
        self.val.is_even()
    }

    fn is_multiple_of(&self, _other: &Self) -> bool {
        true
    }

    fn is_odd(&self) -> bool {
        self.val.is_odd()
    }

    fn lcm(&self, other: &Self) -> Self {
        Self::new(*std::cmp::max(&self.val, &other.val))
    }

    fn mod_floor(&self, other: &Self) -> Self {
        Self {
            val: self.val.mod_floor(&other.val),
        }
    }
}

impl Signed for FeltU64 {
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
            FeltU64::zero()
        } else if self.is_positive() {
            FeltU64::one()
        } else {
            FeltU64::max_value()
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && self.val < OXFOI_PRIME
    }

    fn is_negative(&self) -> bool {
        !(self.is_positive() || self.is_zero())
    }
}

impl Shl<u32> for FeltU64 {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        FeltU64 {
            val: (self.val).shl(other).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Shl<u32> for &FeltU64 {
    type Output = FeltU64;
    fn shl(self, other: u32) -> Self::Output {
        FeltU64 {
            val: (&self.val).shl(other).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Shl<usize> for FeltU64 {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        FeltU64 {
            val: (self.val).shl(other).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Shl<usize> for &FeltU64 {
    type Output = FeltU64;
    fn shl(self, other: usize) -> Self::Output {
        FeltU64 {
            val: (&self.val).shl(other).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Shr<u32> for FeltU64 {
    type Output = Self;
    fn shr(self, other: u32) -> Self::Output {
        FeltU64 {
            val: self.val.shr(other).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl Shr<u32> for &FeltU64 {
    type Output = FeltU64;
    fn shr(self, other: u32) -> Self::Output {
        FeltU64 {
            val: (&self.val).shr(other).mod_floor(&OXFOI_PRIME),
        }
    }
}

impl ShrAssign<usize> for FeltU64 {
    fn shr_assign(&mut self, other: usize) {
        self.val = (&self.val).shr(other).mod_floor(&OXFOI_PRIME);
    }
}

impl BitAnd for &FeltU64 {
    type Output = FeltU64;
    fn bitand(self, rhs: Self) -> Self::Output {
        FeltU64 {
            val: &self.val & &rhs.val,
        }
    }
}

impl BitAnd<&FeltU64> for FeltU64 {
    type Output = Self;
    fn bitand(self, rhs: &FeltU64) -> Self::Output {
        FeltU64 {
            val: self.val & &rhs.val,
        }
    }
}

impl BitAnd<FeltU64> for &FeltU64 {
    type Output = FeltU64;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        FeltU64 {
            val: &self.val & rhs.val,
        }
    }
}

impl BitOr for &FeltU64 {
    type Output = FeltU64;
    fn bitor(self, rhs: Self) -> Self::Output {
        FeltU64 {
            val: &self.val | &rhs.val,
        }
    }
}

impl BitXor for &FeltU64 {
    type Output = FeltU64;
    fn bitxor(self, rhs: Self) -> Self::Output {
        FeltU64 {
            val: &self.val ^ &rhs.val,
        }
    }
}

impl ToPrimitive for FeltU64 {
    fn to_u64(&self) -> Option<u64> {
        self.val.to_u64()
    }

    fn to_i64(&self) -> Option<i64> {
        self.val.to_i64()
    }

    fn to_usize(&self) -> Option<usize> {
        self.val.to_usize()
    }
}

impl FromPrimitive for FeltU64 {
    fn from_u64(n: u64) -> Option<Self> {
        u64::from_u64(n).map(|n| Self { val: n })
    }

    fn from_i64(n: i64) -> Option<Self> {
        u64::from_i64(n).map(|n| Self { val: n })
    }

    fn from_usize(n: usize) -> Option<Self> {
        u64::from_usize(n).map(|n| Self { val: n })
    }
}

impl fmt::Display for FeltU64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl fmt::Debug for FeltU64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    // Tests that the result of adding two zeros is zero.
    fn add_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);

        assert_eq!(a + b, c);
    }

    #[test]
    // Tests that the result of performing add assign with two zeros is zero.
    fn add_assign_zeros() {
        let mut a = FeltU64::new(0);
        let b = FeltU64::new(0);
        a += b;
        let c = FeltU64::new(0);

        assert_eq!(a, c);
    }
    #[test]
    // Tests that the result of performing a bitwise "and" operation with two zeros is zero.
    fn bit_and_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);

        assert_eq!(&a & &b, c);
    }
    #[test]
    // Tests that the result of performing a bitwise "or" operation with two zeros is zero.

    fn bit_or_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);

        assert_eq!(&a | &b, c);
    }

    #[test]
    // Tests that the result of performing a bitwise "xor" operation with two zeros results in zero.
    fn bit_xor_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);

        assert_eq!(&a ^ &b, c);
    }

    #[test]
    #[should_panic]
    // Tests that the result of performing a division by zero results in panic.
    fn div_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let _ = a / b;
    }

    #[test]
    #[should_panic]
    // Tests that the result of performing a division by zero results in panic.
    fn div_zeros_ref() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let _ = &a / &b;
    }

    #[test]
    // Tests that the result of multiplying two zeros is zero.
    fn mul_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);

        assert_eq!(a * b, c);
    }

    #[test]
    // Tests that the result of multiplying two zeros with assignment is zero.
    fn mul_assign_zeros() {
        let mut a = FeltU64::new(0);
        let b = FeltU64::new(0);
        a *= &b;
        let c = FeltU64::new(0);

        assert_eq!(a, c);
    }

    #[test]
    // Tests that the result of subtracting two zeros is zero.
    fn sub_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);

        assert_eq!(a - b, c);
    }

    #[test]
    // Tests that the result of subtracting two zeros with assignment is zero.
    fn sub_assign_zeros() {
        let mut a = FeltU64::new(0);
        let b = FeltU64::new(0);
        a -= b;
        let c = FeltU64::new(0);

        assert_eq!(a, c);
    }

    #[test]
    fn sub_usize_felt() {
        let a = FeltU64::new(4u32);
        let b = FeltU64::new(2u32);

        assert_eq!(6usize - &a, b);
        assert_eq!(6usize - a, b);
    }

    #[test]
    // Tests that the negative of zero is zero
    fn negate_zero() {
        let a = FeltU64::new(0);
        let b = a.neg();
        assert_eq!(
            b,
            FeltU64::from_str_radix("0", 10).expect("Couldn't parse int")
        );

        let c = FeltU64::from_str_radix("0", 10).expect("Couldn't parse int");
        let d = c.neg();
        assert_eq!(d, FeltU64::new(0));
    }

    #[test]
    // Tests a shift left operation performed on a felt of value zero
    fn shift_left_zero() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let result = &a << 10_u32;
        assert_eq!(result, b)
    }

    #[test]
    // Tests a shift right operation performed on a felt of value zero
    fn shift_right_zero() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let result = &a >> 10_u32;
        assert_eq!(result, b)
    }

    #[test]
    // Tests a shift right operation with assignment performed on a felt of value zero
    fn shift_right_assign_zero() {
        let mut a = FeltU64::new(0);
        let b = FeltU64::new(0);
        a >>= 10;
        assert_eq!(a, b)
    }

    #[test]
    // Test that an iterative sum of zeros results in zero
    fn sum_zeros() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(0);
        let v = vec![a, b, c];
        let result: FeltU64 = v.into_iter().sum();
        assert_eq!(result, FeltU64::new(0))
    }

    #[test]
    // Tests that the remainder of a division where the dividend is 0, results in 0
    fn rem_zero() {
        let a = FeltU64::new(0);
        let b = FeltU64::new(0);
        let c = FeltU64::new(10);
        let d = FeltU64::new(0);
        assert_eq!(a.clone() % b, d);
        assert_eq!(a % c, d)
    }

    proptest! {
        #[test]
        // Property-based test that ensures, for 100 pairs of values that are randomly generated each time tests are run, that performing a subtraction returns a result that is inside of the range [0, p].
        fn sub_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = x - y;
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < &p, "{}", as_uint);
        }

        #[test]
        // Property-based test that ensures, for 100 pairs of values that are randomly generated each time tests are run, that performing a subtraction returns a result that is inside of the range [0, p].
        fn sub_assign_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let mut x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            x -= y;
            let as_uint = &x.to_biguint();
            prop_assert!(as_uint < &p, "{}", as_uint);
        }

        #[test]
        // Property-based test that ensures that the remainder of a division between two random bigint felts returns 0. The test is performed 100 times each run.
        fn rem_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();

            let result = x % y;
            prop_assert!(result.is_zero());
        }
        // Tests that the result of adding two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        #[test]
        fn add_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &OXFOI_PRIME;
            let result = x + y;
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < &p, "{}", as_uint);

        }
        #[test]
        // Tests that the result of performing add assign on two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn add_assign_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let mut x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &OXFOI_PRIME;
            x += y;
            let as_uint = &x.to_biguint();
            prop_assert!(as_uint < &p, "{}", as_uint);
        }

        #[test]
        // Tests that the result of performing the bitwise "and" operation on two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn bitand_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = &x & &y;
            let as_uint = result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
        #[test]
        // Tests that the result of performing the bitwise "or" operation on two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn bitor_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = &x | &y;
            let as_uint = result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
        #[test]
        // Tests that the result of performing the bitwise "xor" operation on two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn bitxor_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = &x ^ &y;
            let as_uint = result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
        #[test]
        // Tests that the result dividing two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn div_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = &x / &y;
            let as_uint = result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
        #[test]
        // Tests that the result multiplying two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn mul_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = &x * &y;
            let as_uint = result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
        #[test]
        // Tests that the result of performing a multiplication with assignment between two random large bigint felts falls within the range [0, p]. This test is performed 100 times each run.
        fn mul_assign_bigint_felts_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)") {
            let mut x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            x *= &y;
            let as_uint = x.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
        #[test]
        // Tests that the result of applying the negative operation to a large bigint felt falls within the range [0, p]. This test is performed 100 times each run.
        fn neg_bigint_felt_within_field(ref x in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = -x;
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < &p, "{}", as_uint);
        }

        #[test]
         // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the left by an amount {y} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
         fn shift_left_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "[0-9]{1,3}") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = y.parse::<u32>().unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let result = x << y;
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < &p, "{}", as_uint);
        }

        #[test]
        // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the right by an amount {y} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
        fn shift_right_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "[0-9]{1,3}") {
           let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
           let y = y.parse::<u32>().unwrap();
           let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
           let result = x >> y;
           let as_uint = &result.to_biguint();
           prop_assert!(as_uint < &p, "{}", as_uint);
       }

       #[test]
       // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the right with assignment by an amount {y} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
       fn shift_right_assign_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "[0-9]{1,3}") {
          let mut x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
          let y = y.parse::<u32>().unwrap();
          let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
          x >>= y.try_into().unwrap();
          let as_uint = &x.to_biguint();
          prop_assert!(as_uint < &p, "{}", as_uint);
        }

        #[test]
        // Property-based test that ensures, vectors of three of values that are randomly generated each time tests are run, that performing an iterative sum returns a result that is inside of the range [0, p]. The test is performed 100 times each run.
        fn sum_bigint_felt_within_field(ref x in "([1-9][0-9]*)", ref y in "([1-9][0-9]*)", ref z in "([1-9][0-9]*)") {
            let x = FeltU64::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = FeltU64::parse_bytes(y.as_bytes(), 10).unwrap();
            let z = FeltU64::parse_bytes(z.as_bytes(), 10).unwrap();
            let p:BigUint = BigUint::parse_bytes(OXFOI_PRIME.to_string().as_bytes(), 16).unwrap();
            let v = vec![x.clone(), y, z];
            let result: FeltU64 = v.into_iter().sum();
            let as_uint = result.to_biguint();
            prop_assert!(&as_uint < &p, "{}", as_uint);
        }
    }
}

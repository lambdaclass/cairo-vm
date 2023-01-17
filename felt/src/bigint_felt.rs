use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint, ToBigInt, U64Digits};
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

use crate::{FeltOps, NewFelt, ParseFeltError, FIELD};

lazy_static! {
    pub static ref CAIRO_PRIME: BigUint =
        (Into::<BigUint>::into(FIELD.0) << 128) + Into::<BigUint>::into(FIELD.1);
    pub static ref SIGNED_FELT_MAX: BigUint = (&*CAIRO_PRIME).shr(1_u32);
    pub static ref CAIRO_SIGNED_PRIME: BigInt = CAIRO_PRIME
        .to_bigint()
        .expect("Conversion BigUint -> BigInt can't fail");
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default, Serialize)]
//pub struct FeltBigInt(BigUint);
pub struct FeltBigInt<const P: (u128, u128)> {
    val: BigUint,
}

macro_rules! from_integer {
    ($type:ty) => {
        impl From<$type> for FeltBigInt<FIELD> {
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
        impl From<$type> for FeltBigInt<FIELD> {
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

impl From<BigUint> for FeltBigInt<FIELD> {
    fn from(value: BigUint) -> Self {
        if value > *CAIRO_PRIME {
            Self(value.mod_floor(&CAIRO_PRIME))
        } else {
            Self(value)
        }
    }
}

impl From<&BigUint> for FeltBigInt<FIELD> {
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

impl From<BigInt> for FeltBigInt<FIELD> {
    fn from(value: BigInt) -> Self {
        (&value).into()
    }
}

impl From<&BigInt> for FeltBigInt<FIELD> {
    fn from(value: &BigInt) -> Self {
        Self(
            value
                .mod_floor(&CAIRO_SIGNED_PRIME)
                .to_biguint()
                .expect("mod_floor is always positive"),
        )
    }
}

impl NewFelt for FeltBigInt<FIELD> {
    fn new<T: Into<Self>>(value: T) -> Self {
        value.into()
    }
}

impl FeltOps for FeltBigInt<FIELD> {
    fn modpow(&self, exponent: &FeltBigInt<FIELD>, modulus: &FeltBigInt<FIELD>) -> Self {
        FeltBigInt {
            val: self.val.modpow(&exponent.val, &modulus.val),
        }
    }

    fn iter_u64_digits(&self) -> U64Digits {
        self.val.iter_u64_digits()
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        self.val.to_bytes_le()
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.val.to_bytes_be()
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
        FeltBigInt {
            val: self.val.sqrt(),
        }
    }

    fn bits(&self) -> u64 {
        self.val.bits()
    }
}

impl Add for FeltBigInt<FIELD> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.val += rhs.val;
        if self.val >= *CAIRO_PRIME {
            self.val -= &*CAIRO_PRIME;
        }
        self
    }
}

impl<'a> Add for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;

    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = &self.val + &rhs.val;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt { val: sum }
    }
}

impl<'a> Add<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;

    fn add(mut self, rhs: &'a FeltBigInt<FIELD>) -> Self::Output {
        self.val += &rhs.val;
        if self.val >= *CAIRO_PRIME {
            self.val -= &*CAIRO_PRIME;
        }
        self
    }
}

impl Add<u32> for FeltBigInt<FIELD> {
    type Output = Self;
    fn add(mut self, rhs: u32) -> Self {
        self.0 += rhs;
        if self.0 >= *CAIRO_PRIME {
            self.0 -= &*CAIRO_PRIME;
        }
        self
    }
}

impl Add<usize> for FeltBigInt<FIELD> {
    type Output = Self;
    fn add(mut self, rhs: usize) -> Self {
        self.val += rhs;
        if self.val >= *CAIRO_PRIME {
            self.val -= &*CAIRO_PRIME;
        }
        self
    }
}

impl<'a> Add<usize> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn add(self, rhs: usize) -> Self::Output {
        let mut sum = &self.val + rhs;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt { val: sum }
    }
}

impl AddAssign for FeltBigInt<FIELD> {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'a> AddAssign<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    fn add_assign(&mut self, rhs: &'a FeltBigInt<FIELD>) {
        *self = &*self + rhs;
    }
}

impl Sum for FeltBigInt<FIELD> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(FeltBigInt::zero(), |mut acc, x| {
            acc += x;
            acc
        })
    }
}

impl Neg for FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self
        } else {
            FeltBigInt {
                val: &*CAIRO_PRIME - self.val,
            }
        }
    }
}

impl<'a> Neg for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self.clone()
        } else {
            FeltBigInt {
                val: &*CAIRO_PRIME - &self.val,
            }
        }
    }
}

impl Sub for FeltBigInt<FIELD> {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        if self.val < rhs.val {
            self.val += &*CAIRO_PRIME;
        }
        self.val -= rhs.val;
        self
    }
}

impl<'a> Sub<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn sub(mut self, rhs: &'a FeltBigInt<FIELD>) -> Self::Output {
        if self.val < rhs.val {
            self.val += &*CAIRO_PRIME;
        }
        self.val -= &rhs.val;
        self
    }
}

impl<'a> Sub for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltBigInt {
            val: if self.val < rhs.val {
                &*CAIRO_PRIME - (&rhs.val - &self.val)
            } else {
                &self.val - &rhs.val
            },
        }
    }
}

impl Sub<u32> for FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn sub(self, rhs: u32) -> Self {
        match (self.val).to_u32() {
            Some(num) if num < rhs => Self(&*CAIRO_PRIME - (rhs - self.val)),
            _ => Self(self.val - rhs),
        }
    }
}

impl<'a> Sub<u32> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn sub(self, rhs: u32) -> Self::Output {
        match (self.val).to_u32() {
            Some(num) if num < rhs => FeltBigInt {
                val: &*CAIRO_PRIME - (rhs - &self.val),
            },
            _ => FeltBigInt {
                val: &self.val - rhs,
            },
        }
    }
}

impl Sub<usize> for FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn sub(self, rhs: usize) -> Self {
        match (self.val).to_usize() {
            Some(num) if num < rhs => FeltBigInt {
                val: &*CAIRO_PRIME - (rhs - num),
            },
            _ => FeltBigInt {
                val: self.val - rhs,
            },
        }
    }
}

impl SubAssign for FeltBigInt<FIELD> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'a> SubAssign<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    fn sub_assign(&mut self, rhs: &'a FeltBigInt<FIELD>) {
        *self = &*self - rhs;
    }
}

impl Sub<FeltBigInt<FIELD>> for usize {
    type Output = FeltBigInt<FIELD>;
    fn sub(self, rhs: FeltBigInt<FIELD>) -> Self::Output {
        self - &rhs
    }
}

impl Sub<&FeltBigInt<FIELD>> for usize {
    type Output = FeltBigInt<FIELD>;
    fn sub(self, rhs: &FeltBigInt<FIELD>) -> Self::Output {
        match (rhs.val).to_usize() {
            Some(num) => {
                if num > self {
                    FeltBigInt {
                        val: &*CAIRO_PRIME - (num - self),
                    }
                } else {
                    FeltBigInt::new(self - num)
                }
            }
            None => FeltBigInt {
                val: &*CAIRO_PRIME - (&rhs.val - self),
            },
        }
    }
}

impl Mul for FeltBigInt<FIELD> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        FeltBigInt {
            val: (self.val * rhs.val).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> Mul for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn mul(self, rhs: Self) -> Self::Output {
        FeltBigInt {
            val: (&self.val * &rhs.val).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> Mul<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn mul(self, rhs: &'a FeltBigInt<FIELD>) -> Self::Output {
        FeltBigInt {
            val: (&self.val * &rhs.val).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> MulAssign<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    fn mul_assign(&mut self, rhs: &'a FeltBigInt<FIELD>) {
        *self = &*self * rhs;
    }
}

impl Pow<u32> for FeltBigInt<FIELD> {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        FeltBigInt {
            val: self.val.pow(rhs).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> Pow<u32> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    #[allow(clippy::needless_borrow)] // the borrow of self.val is necessary becase it's of the type BigUInt, which doesn't implement the Copy trait
    fn pow(self, rhs: u32) -> Self::Output {
        FeltBigInt {
            val: (&self.val).pow(rhs).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl Div for FeltBigInt<FIELD> {
    type Output = Self;
    // In Felts `x / y` needs to be expressed as `x * y^-1`
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        let x = rhs
            .val
            .to_bigint() // Always succeeds for BigUint -> BigInt
            .unwrap()
            .extended_gcd(&CAIRO_SIGNED_PRIME)
            .x;
        self * &FeltBigInt::from(x)
    }
}

impl<'a> Div for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    // In Felts `x / y` needs to be expressed as `x * y^-1`
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        let x = rhs
            .val
            .to_bigint() // Always succeeds for BitUint -> BigInt
            .unwrap()
            .extended_gcd(&CAIRO_SIGNED_PRIME)
            .x;
        self * &FeltBigInt::from(x)
    }
}

impl<'a> Div<FeltBigInt<FIELD>> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    // In Felts `x / y` needs to be expressed as `x * y^-1`
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: FeltBigInt<FIELD>) -> Self::Output {
        let x = rhs
            .val
            .to_bigint() // Always succeeds for BitUint -> BigInt
            .unwrap()
            .extended_gcd(&CAIRO_SIGNED_PRIME)
            .x;
        self * &FeltBigInt::from(x)
    }
}

impl Rem for FeltBigInt<FIELD> {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        FeltBigInt {
            val: self.val % rhs.val,
        }
    }
}

impl<'a> Rem<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    type Output = Self;
    fn rem(self, rhs: &'a FeltBigInt<FIELD>) -> Self::Output {
        FeltBigInt {
            val: self.val % &rhs.val,
        }
    }
}

impl Zero for FeltBigInt<FIELD> {
    fn zero() -> Self {
        Self(BigUint::zero())
    }

    fn is_zero(&self) -> bool {
        self.val.is_zero()
    }
}

impl One for FeltBigInt<FIELD> {
    fn one() -> Self {
        Self(BigUint::one())
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self.val.is_one()
    }
}

impl Bounded for FeltBigInt<FIELD> {
    fn min_value() -> Self {
        Self::zero()
    }
    fn max_value() -> Self {
        Self(&*CAIRO_PRIME - 1_u32)
    }
}

impl Num for FeltBigInt<FIELD> {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match BigUint::from_str_radix(string, radix) {
            Ok(num) => Ok(FeltBigInt::new(num)),
            Err(_) => Err(ParseFeltError),
        }
    }
}

impl Integer for FeltBigInt<FIELD> {
    fn div_floor(&self, other: &Self) -> Self {
        FeltBigInt {
            val: self.val.div_floor(&other.val),
        }
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        div_rem(self, other)
    }

    fn divides(&self, other: &Self) -> bool {
        self.val.divides(&other.val)
    }

    fn gcd(&self, other: &Self) -> Self {
        Self(self.val.gcd(&other.val))
    }

    fn is_even(&self) -> bool {
        self.val.is_even()
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        self.val.is_multiple_of(&other.val)
    }

    fn is_odd(&self) -> bool {
        self.val.is_odd()
    }

    fn lcm(&self, other: &Self) -> Self {
        Self::new(self.val.lcm(&other.val))
    }

    fn mod_floor(&self, other: &Self) -> Self {
        Self(self.val.mod_floor(&other.val))
    }
}

impl Signed for FeltBigInt<FIELD> {
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
        !self.is_zero() && self.val < *SIGNED_FELT_MAX
    }

    fn is_negative(&self) -> bool {
        !(self.is_positive() || self.is_zero())
    }
}

impl Shl<u32> for FeltBigInt<FIELD> {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt {
            val: (self.val).shl(other).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> Shl<u32> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt {
            val: (&self.val).shl(other).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl Shl<usize> for FeltBigInt<FIELD> {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        FeltBigInt {
            val: (self.val).shl(other).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> Shl<usize> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn shl(self, other: usize) -> Self::Output {
        FeltBigInt {
            val: (&self.val).shl(other).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl Shr<u32> for FeltBigInt<FIELD> {
    type Output = Self;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt {
            val: self.val.shr(other).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl<'a> Shr<u32> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt {
            val: (&self.val).shr(other).mod_floor(&CAIRO_PRIME),
        }
    }
}

impl ShrAssign<usize> for FeltBigInt<FIELD> {
    fn shr_assign(&mut self, other: usize) {
        self.val = (&self.val).shr(other).mod_floor(&CAIRO_PRIME);
    }
}

impl<'a> BitAnd for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn bitand(self, rhs: Self) -> Self::Output {
        FeltBigInt {
            val: &self.val & &rhs.val,
        }
    }
}

impl<'a> BitAnd<&'a FeltBigInt<FIELD>> for FeltBigInt<FIELD> {
    type Output = Self;
    fn bitand(self, rhs: &'a FeltBigInt<FIELD>) -> Self::Output {
        FeltBigInt {
            val: self.val & &rhs.val,
        }
    }
}

impl<'a> BitAnd<FeltBigInt<FIELD>> for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        FeltBigInt {
            val: &self.val & rhs.val,
        }
    }
}

impl<'a> BitOr for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn bitor(self, rhs: Self) -> Self::Output {
        FeltBigInt {
            val: &self.val | &rhs.val,
        }
    }
}

impl<'a> BitXor for &'a FeltBigInt<FIELD> {
    type Output = FeltBigInt<FIELD>;
    fn bitxor(self, rhs: Self) -> Self::Output {
        FeltBigInt {
            val: &self.val ^ &rhs.val,
        }
    }
}

pub fn div_rem(
    x: &FeltBigInt<FIELD>,
    y: &FeltBigInt<FIELD>,
) -> (FeltBigInt<FIELD>, FeltBigInt<FIELD>) {
    let (d, m) = x.val.div_mod_floor(&y.val);
    (FeltBigInt { val: d }, FeltBigInt { val: m })
}

impl ToPrimitive for FeltBigInt<FIELD> {
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

impl FromPrimitive for FeltBigInt<FIELD> {
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

impl fmt::Display for FeltBigInt<FIELD> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl fmt::Debug for FeltBigInt<FIELD> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
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

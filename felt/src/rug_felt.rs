use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign, U64Digits};
use num_integer::Integer;
use num_traits::{Bounded, FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use rug::Complete;
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
    pub static ref CAIRO_PRIME: rug::Integer =
        (rug::Integer::from(FIELD.0) << 128) + rug::Integer::from(FIELD.1);
    pub static ref SIGNED_FELT_MAX: rug::Integer =
        (rug::Integer::from(FIELD.0) << 127) + rug::Integer::from(FIELD.1) >> 1;
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default)]
pub struct FeltRug(rug::Integer);

/*impl<T: Into<rug::Integer>> From<T> for FeltRug {
    fn from(value: T) -> Self {
        let mut rem = value.into();
        if &rem > &*CAIRO_PRIME {
            rem %= &*CAIRO_PRIME;
        }
        Self(rem)
    }
}*/
impl From<u32> for FeltRug {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl From<u64> for FeltRug {
    fn from(value: u64) -> Self {
        Self(value.into())
    }
}

impl From<u128> for FeltRug {
    fn from(value: u128) -> Self {
        Self(value.into())
    }
}

impl From<usize> for FeltRug {
    fn from(value: usize) -> Self {
        Self(value.into())
    }
}

impl From<i32> for FeltRug {
    fn from(value: i32) -> Self {
        Self(
            if value < 0 {
                (&*CAIRO_PRIME + value).complete()
            } else {
                value.into()
            })
    }
}

impl From<i128> for FeltRug {
    fn from(value: i128) -> Self {
        Self(
            if value < 0 {
                (&*CAIRO_PRIME + value).complete()
            } else {
                value.into()
            })
    }
}

impl From<rug::Integer> for FeltRug {
    fn from(value: rug::Integer) -> Self {
        let mut rem = value.into();
        if &rem > &*CAIRO_PRIME {
            rem %= &*CAIRO_PRIME;
        }
        Self(rem)
    }
}

impl NewFelt for FeltRug {
    fn new<T: Into<Self>>(value: T) -> Self {
        value.into()
    }
}

impl FeltOps for FeltRug {
    fn modpow(&self, exponent: &FeltRug, modulus: &FeltRug) -> Self {
        /*FeltRug(self.0.modpow(&exponent.0, &modulus.0))
         */
        todo!();
    }

    fn mod_floor(&self, other: &FeltRug) -> Self {
        /*FeltRug(self.0.mod_floor(&other.0))
         */
        todo!();
    }

    fn div_floor(&self, other: &FeltRug) -> Self {
        /*FeltRug(self.0.div_floor(&other.0))
         */
        todo!();
    }

    fn div_mod_floor(&self, other: &FeltRug) -> (Self, Self) {
        /*let (d, m) = self.0.div_mod_floor(&other.0);
        (FeltRug(d), FeltRug(m))
        */
        todo!();
    }

    fn iter_u64_digits(&self) -> U64Digits {
        /*self.0.iter_u64_digits()
         */
        todo!();
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        /*self.0.to_signed_bytes_le()
         */
        todo!();
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        /*self.0.to_bytes_be().1
         */
        todo!();
    }

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        Some(Self::new(
            rug::Integer::parse_radix(buf, radix as i32).ok()?.complete(),
        ))
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        /*let bigint = BigInt::from_bytes_be(Sign::Plus, bytes);
        let string = bigint.to_str_radix(16);
        Self::new(rug::Integer::parse_radix(string, 16).unwrap())*/
        todo!()
    }

    fn to_str_radix(&self, radix: u32) -> String {
        /*self.0.to_str_radix(radix)
         */
        todo!();
    }

    fn div_rem(&self, other: &FeltRug) -> (FeltRug, FeltRug) {
        /*div_rem(self, other)
         */
        todo!();
    }

    fn to_bigint(&self) -> BigInt {
        /*if self.is_negative() {
            &self.0 - &*CAIRO_PRIME
        } else {
            self.0.clone()
        }
            */
        todo!();
    }

    fn to_bigint_unsigned(&self) -> BigInt {
        /*self.0.clone()
         */
        todo!();
    }

    fn mul_inverse(&self) -> Self {
        /*if self.is_zero() {
            return Felt::zero();
        }
        let mut a = self.0.clone();
        let mut b = CAIRO_PRIME.clone();
        let (mut x, mut y, mut t, mut s) =
            (BigInt::one(), BigInt::zero(), BigInt::zero(), BigInt::one());
        let (mut quot, mut rem);
        while !b.is_zero() {
            (quot, rem) = (a.div_floor(&b), a.mod_floor(&b));
            (a, b, t, s, x, y) = (b, rem, x - &quot * &t, y - quot * &s, t, s);
        }
        Self((x.mod_floor(&CAIRO_PRIME) + &*CAIRO_PRIME).mod_floor(&CAIRO_PRIME))
            */
        todo!();
    }

    fn sqrt(&self) -> Self {
        /*FeltRug(self.0.sqrt())
         */
        todo!();
    }
}

impl Add for FeltRug {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut sum = self.0 + rhs.0;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltRug(sum)
    }
}

impl<'a> Add for &'a FeltRug {
    type Output = FeltRug;

    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = rug::Integer::from(&self.0 + &rhs.0);
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltRug(sum)
    }
}

impl<'a> Add<&'a FeltRug> for FeltRug {
    type Output = FeltRug;

    fn add(self, rhs: &'a FeltRug) -> Self::Output {
        /*let mut sum = self.0 + &rhs.0;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltRug(sum)
            */
        todo!();
    }
}

impl Add<u32> for FeltRug {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        /*let mut sum = self.0 + rhs;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltRug(sum)
            */
        todo!();
    }
}

impl Add<usize> for FeltRug {
    type Output = Self;
    fn add(self, rhs: usize) -> Self {
        /*let mut sum = self.0 + rhs;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltRug(sum)
            */
        todo!();
    }
}

impl<'a> Add<usize> for &'a FeltRug {
    type Output = FeltRug;
    fn add(self, rhs: usize) -> Self::Output {
        let mut sum = (&self.0 + &rhs).complete();
        if &sum >= &*CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltRug(sum)
    }
}

impl AddAssign for FeltRug {
    fn add_assign(&mut self, rhs: Self) {
        /* *self = &*self + &rhs;
         */
        todo!();
    }
}

impl<'a> AddAssign<&'a FeltRug> for FeltRug {
    fn add_assign(&mut self, rhs: &'a FeltRug) {
        /* *self = &*self + rhs;
         */
        todo!();
    }
}

impl Sum for FeltRug {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        /*iter.fold(FeltRug::zero(), Add::add)
         */
        todo!();
    }
}

impl Neg for FeltRug {
    type Output = FeltRug;
    fn neg(self) -> Self::Output {
        /*if self.is_negative() {
            FeltRug(&*CAIRO_PRIME - self.0)
        } else if self.is_positive() {
            FeltRug(-(self.0 - &*CAIRO_PRIME))
        } else {
            self
        }
            */
        todo!();
    }
}

impl<'a> Neg for &'a FeltRug {
    type Output = FeltRug;
    fn neg(self) -> Self::Output {
        /*if self.is_negative() {
            FeltRug(&*CAIRO_PRIME - &self.0)
        } else if self.is_positive() {
            FeltRug(-(&self.0 - &*CAIRO_PRIME))
        } else {
            FeltRug::new(&self.0)
        }
            */
        todo!();
    }
}

impl Sub for FeltRug {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        /*let mut sub = self.0 - rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltRug(sub)
            */
        todo!();
    }
}

impl<'a> Sub<&'a FeltRug> for FeltRug {
    type Output = FeltRug;
    fn sub(self, rhs: &'a FeltRug) -> Self::Output {
        /*let mut sub = self.0 - &rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltRug(sub)
            */
        todo!();
    }
}

impl<'a> Sub for &'a FeltRug {
    type Output = FeltRug;
    fn sub(self, rhs: Self) -> Self::Output {
        /*let mut sub = &self.0 - &rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltRug(sub)
            */
        todo!();
    }
}

impl Sub<u32> for FeltRug {
    type Output = FeltRug;
    fn sub(self, rhs: u32) -> Self::Output {
        todo!();
    }
}

impl<'a> Sub<usize> for &'a FeltRug {
    type Output = FeltRug;
    fn sub(self, rhs: usize) -> Self::Output {
        todo!();
    }
}

impl SubAssign for FeltRug {
    fn sub_assign(&mut self, rhs: Self) {
        /* *self = &*self - &rhs;
         */
        todo!();
    }
}

impl<'a> SubAssign<&'a FeltRug> for FeltRug {
    fn sub_assign(&mut self, rhs: &'a FeltRug) {
        /* *self = &*self - rhs;
         */
        todo!();
    }
}

impl Mul for FeltRug {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        /*FeltRug((self.0 * rhs.0).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> Mul for &'a FeltRug {
    type Output = FeltRug;
    fn mul(self, rhs: Self) -> Self::Output {
        /*FeltRug((&self.0 * &rhs.0).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> Mul<&'a FeltRug> for FeltRug {
    type Output = FeltRug;
    fn mul(self, rhs: &'a FeltRug) -> Self::Output {
        /*FeltRug((&self.0 * &rhs.0).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> MulAssign<&'a FeltRug> for FeltRug {
    fn mul_assign(&mut self, rhs: &'a FeltRug) {
        /* *self = &*self * rhs;
         */
        todo!();
    }
}

impl Pow<u32> for FeltRug {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        /*FeltRug(self.0.pow(rhs).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> Pow<u32> for &'a FeltRug {
    type Output = FeltRug;
    fn pow(self, rhs: u32) -> Self::Output {
        /*FeltRug((&self.0).pow(rhs).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl Div for FeltRug {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        /*FeltRug(self.0 / rhs.0)
         */
        todo!();
    }
}

impl<'a> Div for &'a FeltRug {
    type Output = FeltRug;
    fn div(self, rhs: Self) -> Self::Output {
        /*FeltRug(&self.0 / &rhs.0)
         */
        todo!();
    }
}

impl<'a> Div<FeltRug> for &'a FeltRug {
    type Output = FeltRug;
    fn div(self, rhs: FeltRug) -> Self::Output {
        /*FeltRug(&self.0 / rhs.0)
         */
        todo!();
    }
}

impl Rem for FeltRug {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        /*FeltRug(self.0 % rhs.0)
         */
        todo!();
    }
}

impl<'a> Rem<&'a FeltRug> for FeltRug {
    type Output = Self;
    fn rem(self, rhs: &'a FeltRug) -> Self::Output {
        /*FeltRug(self.0 % &rhs.0)
         */
        todo!();
    }
}

impl Zero for FeltRug {
    fn zero() -> Self {
        /*Self(BigInt::zero())
         */
        todo!();
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for FeltRug {
    fn one() -> Self {
        Self(rug::Integer::one())
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        /*self.0.is_one()
         */
        todo!();
    }
}

impl Bounded for FeltRug {
    fn min_value() -> Self {
        /*Self::zero()
         */
        todo!();
    }
    fn max_value() -> Self {
        /*Self::zero() - Self::one()
         */
        todo!();
    }
}

impl Num for FeltRug {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match rug::Integer::from_str_radix(string, radix as i32) {
            Ok(num) => Ok(FeltRug::new(num)),
            Err(_) => Err(ParseFeltError),
        }
    }
}

impl Signed for FeltRug {
    fn abs(&self) -> Self {
        /*if self.is_negative() {
            self.neg()
        } else {
            self.clone()
        }
            */
        todo!();
    }

    fn abs_sub(&self, other: &Self) -> Self {
        /*let sub = self - other;
        sub.abs()
        */
        todo!();
    }

    fn signum(&self) -> Self {
        /*if self.is_zero() {
            FeltRug::zero()
        } else if self.is_positive() {
            FeltRug::one()
        } else {
            FeltRug::zero() - FeltRug::one()
        }
            */
        todo!();
    }

    fn is_positive(&self) -> bool {
        /* !self.is_zero() && self.0 < *SIGNED_FELT_MAX
         */
        todo!();
    }

    fn is_negative(&self) -> bool {
        /* !(self.is_positive() || self.is_zero())
         */
        todo!();
    }
}

impl Shl<u32> for FeltRug {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        /*FeltRug((self.0).shl(other).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> Shl<u32> for &'a FeltRug {
    type Output = FeltRug;
    fn shl(self, other: u32) -> Self::Output {
        /*FeltRug((&self.0).shl(other).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl Shl<usize> for FeltRug {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        /*FeltRug((self.0).shl(other).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> Shl<usize> for &'a FeltRug {
    type Output = FeltRug;
    fn shl(self, other: usize) -> Self::Output {
        /*FeltRug((&self.0).shl(other).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl Shr<u32> for FeltRug {
    type Output = Self;
    fn shr(self, other: u32) -> Self::Output {
        /*FeltRug(self.0.shr(other).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl<'a> Shr<u32> for &'a FeltRug {
    type Output = FeltRug;
    fn shr(self, other: u32) -> Self::Output {
        /*FeltRug((&self.0).shr(other).mod_floor(&CAIRO_PRIME))
         */
        todo!();
    }
}

impl ShrAssign<usize> for FeltRug {
    fn shr_assign(&mut self, other: usize) {
        /*self.0 = (&self.0).shr(other).mod_floor(&CAIRO_PRIME);
         */
        todo!();
    }
}

impl<'a> BitAnd for &'a FeltRug {
    type Output = FeltRug;
    fn bitand(self, rhs: Self) -> Self::Output {
        /*FeltRug(&self.0 & &rhs.0)
         */
        todo!();
    }
}

impl<'a> BitAnd<&'a FeltRug> for FeltRug {
    type Output = Self;
    fn bitand(self, rhs: &'a FeltRug) -> Self::Output {
        /*FeltRug(self.0 & &rhs.0)
         */
        todo!();
    }
}

impl<'a> BitAnd<FeltRug> for &'a FeltRug {
    type Output = FeltRug;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        /*FeltRug(&self.0 & rhs.0)
         */
        todo!();
    }
}

impl<'a> BitOr for &'a FeltRug {
    type Output = FeltRug;
    fn bitor(self, rhs: Self) -> Self::Output {
        /*FeltRug(&self.0 | &rhs.0)
         */
        todo!();
    }
}

impl<'a> BitXor for &'a FeltRug {
    type Output = FeltRug;
    fn bitxor(self, rhs: Self) -> Self::Output {
        /*FeltRug(&self.0 ^ &rhs.0)
         */
        todo!();
    }
}

pub fn div_rem(x: &FeltRug, y: &FeltRug) -> (FeltRug, FeltRug) {
    /*let (d, m) = x.0.div_mod_floor(&y.0);
    (FeltRug(d), FeltRug(m))
    */
    todo!();
}

impl ToPrimitive for FeltRug {
    fn to_u64(&self) -> Option<u64> {
        /*self.0.to_u64()
         */
        todo!();
    }

    fn to_i64(&self) -> Option<i64> {
        self.0.to_i64()
    }

    fn to_usize(&self) -> Option<usize> {
        self.0.to_usize()
    }
}

impl FromPrimitive for FeltRug {
    fn from_i64(n: i64) -> Option<Self> {
        /*BigInt::from_i64(n).map(Self)
         */
        todo!();
    }

    fn from_u64(n: u64) -> Option<Self> {
        /*BigInt::from_u64(n).map(Self)
         */
        todo!();
    }

    fn from_usize(n: usize) -> Option<Self> {
        rug::Integer::from_usize(n).map(Self)
    }
}

impl fmt::Display for FeltRug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /*if self.is_negative() {
            write!(f, "-{}", self.abs().0)
        } else {
            write!(f, "{}", self.0)
        }
          */
        todo!();
    }
}

impl fmt::Debug for FeltRug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /*write!(f, "{}", self.0)
         */
        todo!();
    }
}

impl fmt::Display for ParseFeltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /*write!(f, "{:?}", ParseFeltError)
         */
        todo!();
    }
}
/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_felts_within_field() {
        let a = FeltRug::new(1);
        let b = FeltRug::new(2);
        let c = FeltRug::new(3);

        assert_eq!(a + b, c);
    }

    #[test]
    fn add_assign_felts_within_field() {
        let mut a = FeltRug::new(1i32);
        let b = FeltRug::new(2i32);
        a += b;
        let c = FeltRug::new(3i32);

        assert_eq!(a, c);
    }

    #[test]
    fn mul_felts_within_field() {
        let a = FeltRug::new(2);
        let b = FeltRug::new(3);
        let c = FeltRug::new(6);

        assert_eq!(a * b, c);
    }

    #[test]
    fn mul_assign_felts_within_field() {
        let mut a = FeltRug::new(2i32);
        let b = FeltRug::new(3i32);
        a *= &b;
        let c = FeltRug::new(6i32);

        assert_eq!(a, c);
    }

    #[test]
    fn sub_felts_within_field() {
        let a = FeltRug::new(3);
        let b = FeltRug::new(2);
        let c = FeltRug::new(1);

        assert_eq!(a - b, c);
    }

    #[test]
    fn sub_assign_felts_within_field() {
        let mut a = FeltRug::new(3i32);
        let b = FeltRug::new(2i32);
        a -= b;
        let c = FeltRug::new(1i32);

        assert_eq!(a, c);
    }

    #[test]
    fn sub_usize_felt() {
        let a = FeltRug::new(4);
        let b = FeltRug::new(2);

        assert_eq!(6usize - &a, b);
        assert_eq!(6usize - a, b);
    }

    #[test]
    fn mul_inverse_test() {
        let a = Felt::new(8713861468_i64);
        let b = a.clone().mul_inverse();
        assert_eq!(a * b, Felt::one());
    }

    #[test]
    fn negate_num() {
        let a = Felt::new(10_i32);
        let b = a.neg();
        assert_eq!(
            b,
            Felt::from_str_radix(
                "3618502788666131213697322783095070105623107215331596699973092056135872020471",
                10
            )
            .expect("Couldn't parse int")
        );

        let c = Felt::from_str_radix(
            "3618502788666131213697322783095070105623107215331596699973092056135872020471",
            10,
        )
        .expect("Couldn't parse int");
        let d = c.neg();
        assert_eq!(d, Felt::new(10_i32));
    }
}*/

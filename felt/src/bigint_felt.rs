use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign, U64Digits};
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

use crate::{Felt, NewFelt, ParseFeltError, FIELD};

lazy_static! {
    pub static ref CAIRO_PRIME: BigInt =
        (Into::<BigInt>::into(FIELD.0) << 128) + Into::<BigInt>::into(FIELD.1);
    pub static ref SIGNED_FELT_MAX: BigInt = (&*CAIRO_PRIME).shr(1_u32);
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default)]
pub struct FeltBigInt(BigInt);

impl From<BigInt> for Felt {
    fn from(value: BigInt) -> Self {
        FeltBigInt(value.mod_floor(&CAIRO_PRIME))
    }
}

impl From<&BigInt> for Felt {
    fn from(value: &BigInt) -> Self {
        FeltBigInt(value.mod_floor(&CAIRO_PRIME))
    }
}

impl From<i32> for Felt {
    fn from(value: i32) -> Self {
        FeltBigInt(if value < 0 {
            &*CAIRO_PRIME + value
        } else {
            Into::<BigInt>::into(value)
        })
    }
}

impl From<i64> for Felt {
    fn from(value: i64) -> Self {
        FeltBigInt(if value < 0 {
            &*CAIRO_PRIME + value
        } else {
            Into::<BigInt>::into(value)
        })
    }
}

impl From<i128> for Felt {
    fn from(value: i128) -> Self {
        FeltBigInt(if value < 0 {
            &*CAIRO_PRIME + value
        } else {
            Into::<BigInt>::into(value)
        })
    }
}

impl From<u32> for Felt {
    fn from(value: u32) -> Self {
        FeltBigInt(Into::<BigInt>::into(value))
    }
}

impl From<u64> for Felt {
    fn from(value: u64) -> Self {
        FeltBigInt(Into::<BigInt>::into(value))
    }
}

impl From<u128> for Felt {
    fn from(value: u128) -> Self {
        FeltBigInt(Into::<BigInt>::into(value))
    }
}

impl From<usize> for Felt {
    fn from(value: usize) -> Self {
        FeltBigInt(Into::<BigInt>::into(value))
    }
}

impl NewFelt for FeltBigInt {
    fn new<T: Into<Felt>>(value: T) -> Self {
        Into::<Felt>::into(value)
    }
}

impl FeltBigInt {
    pub fn modpow(&self, exponent: &FeltBigInt, modulus: &FeltBigInt) -> Self {
        FeltBigInt(self.0.modpow(&exponent.0, &modulus.0))
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
    /*
        /// Naive mul inverse using Fermats little theorem
        /// a^(m - 1) mod m = 1 if m prime
        /// a^(m - 2) mod m = a^(-1)
        pub fn mul_inverse(&self) -> Self {
            let mut exponent = FeltBigInt::zero() - FeltBigInt::new(2);
            let mut res = FeltBigInt::one();
            while !exponent.is_zero() {
                res *= self;
                exponent -= FeltBigInt::one();
            }
            res
        }
    */
    pub fn iter_u64_digits(&self) -> U64Digits {
        self.0.iter_u64_digits()
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

    pub fn div_rem(&self, other: &FeltBigInt) -> (FeltBigInt, FeltBigInt) {
        div_rem(self, other)
    }

    pub fn to_bigint(&self) -> BigInt {
        if self.is_negative() {
            &self.0 - &*CAIRO_PRIME
        } else {
            self.0.clone()
        }
    }

    pub fn to_bigint_unsigned(&self) -> BigInt {
        self.0.clone()
    }

    pub fn mul_inverse(&self) -> Self {
        if self.is_zero() {
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
    }
}

impl Bounded for FeltBigInt {
    fn min_value() -> Self {
        Self::zero()
    }
    fn max_value() -> Self {
        Self::zero() - Self::one()
    }
}

impl Zero for FeltBigInt {
    fn zero() -> Self {
        Self(BigInt::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for FeltBigInt {
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
    fn from_i64(n: i64) -> Option<Self> {
        BigInt::from_i64(n).map(Self)
    }

    fn from_u64(n: u64) -> Option<Self> {
        BigInt::from_u64(n).map(Self)
    }

    fn from_usize(n: usize) -> Option<Self> {
        BigInt::from_usize(n).map(Self)
    }
}

impl Num for FeltBigInt {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match BigInt::from_str_radix(string, radix) {
            Ok(num) => Ok(FeltBigInt::new(num)),
            Err(_) => Err(ParseFeltError),
        }
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
        let sub = self - other;
        sub.abs()
    }

    fn signum(&self) -> Self {
        if self.is_zero() {
            FeltBigInt::zero()
        } else if self.is_positive() {
            FeltBigInt::one()
        } else {
            FeltBigInt::zero() - FeltBigInt::one()
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero() && self.0 < *SIGNED_FELT_MAX
    }

    fn is_negative(&self) -> bool {
        !(self.is_positive() || self.is_zero())
    }
}

impl Neg for FeltBigInt {
    type Output = FeltBigInt;
    fn neg(self) -> Self::Output {
        if self.is_negative() {
            FeltBigInt(&*CAIRO_PRIME - self.0)
        } else if self.is_positive() {
            FeltBigInt(-(self.0 - &*CAIRO_PRIME))
        } else {
            self
        }
    }
}

impl<'a> Neg for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn neg(self) -> Self::Output {
        if self.is_negative() {
            FeltBigInt(&*CAIRO_PRIME - &self.0)
        } else if self.is_positive() {
            FeltBigInt(-(&self.0 - &*CAIRO_PRIME))
        } else {
            FeltBigInt::new(&self.0)
        }
    }
}

impl Add for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut sum = self.0 + rhs.0;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt(sum)
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

    fn add(self, rhs: &'a FeltBigInt) -> Self::Output {
        let mut sum = self.0 + &rhs.0;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt(sum)
    }
}

impl Add<u32> for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        let mut sum = self.0 + rhs;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt(sum)
    }
}

impl Add<usize> for FeltBigInt {
    type Output = Self;
    fn add(self, rhs: usize) -> Self {
        let mut sum = self.0 + rhs;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltBigInt(sum)
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

impl Sub for FeltBigInt {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut sub = self.0 - rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltBigInt(sub)
    }
}

impl<'a> Sub<&'a FeltBigInt> for FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: &'a FeltBigInt) -> Self::Output {
        let mut sub = self.0 - &rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltBigInt(sub)
    }
}

impl<'a> Sub for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut sub = &self.0 - &rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltBigInt(sub)
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
        let mut sub = self - &rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltBigInt(sub)
    }
}

impl Sub<FeltBigInt> for u32 {
    type Output = FeltBigInt;

    fn sub(self, rhs: FeltBigInt) -> Self::Output {
        FeltBigInt((BigInt::from(self) - rhs.0).mod_floor(&CAIRO_PRIME))
    }
}

impl Sub<&FeltBigInt> for u32 {
    type Output = FeltBigInt;

    fn sub(self, rhs: &FeltBigInt) -> Self::Output {
        let mut sub = self - &rhs.0;
        if sub.is_negative() {
            sub += &*CAIRO_PRIME;
        }
        FeltBigInt(sub)
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

impl Shl<u32> for FeltBigInt {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt((self.0).shl(other).mod_floor(&CAIRO_PRIME))
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

impl ShrAssign<usize> for FeltBigInt {
    fn shr_assign(&mut self, other: usize) {
        self.0 = (&self.0).shr(other).mod_floor(&CAIRO_PRIME);
    }
}

impl<'a> Shr<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shr(self, other: u32) -> Self::Output {
        FeltBigInt((&self.0).shr(other).mod_floor(&CAIRO_PRIME))
    }
}

impl<'a> Shl<u32> for &'a FeltBigInt {
    type Output = FeltBigInt;
    fn shl(self, other: u32) -> Self::Output {
        FeltBigInt((&self.0).shl(other).mod_floor(&CAIRO_PRIME))
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
        let a = FeltBigInt::new(4);
        let b = FeltBigInt::new(2);

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
}

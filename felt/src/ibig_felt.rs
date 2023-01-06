use std::{
    fmt,
    iter::Sum,
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign,
        Shl, Shr, ShrAssign, Sub, SubAssign,
    },
    str,
};

use ibig::{modular::ModuloRing, IBig, UBig};
use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint, U64Digits};
use num_integer::Integer;
use num_traits::{Bounded, FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use serde::Deserialize;

use crate::{FeltOps, NewFelt, ParseFeltError, FIELD};

lazy_static! {
    pub static ref CAIRO_PRIME: UBig = (UBig::from(FIELD.0) << 128) + UBig::from(FIELD.1);
    pub static ref CAIRO_MODULO_RING: ModuloRing =
        ModuloRing::new(&((UBig::from(FIELD.0) << 128) + UBig::from(FIELD.1)));
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default)]
pub struct FeltIBig(UBig);

macro_rules! from_integer {
    ($type:ty) => {
        impl From<$type> for FeltIBig {
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
        impl From<$type> for FeltIBig {
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

impl From<IBig> for FeltIBig {
    fn from(value: IBig) -> Self {
        Self(CAIRO_MODULO_RING.from(value).residue())
    }
}

impl From<UBig> for FeltIBig {
    fn from(value: UBig) -> Self {
        Self(CAIRO_MODULO_RING.from(value).residue())
    }
}

impl From<&FeltIBig> for FeltIBig {
    fn from(value: &FeltIBig) -> Self {
        value.into()
    }
}

impl From<BigUint> for FeltIBig {
    fn from(value: BigUint) -> Self {
        todo!();
    }
}

impl From<BigInt> for FeltIBig {
    fn from(value: BigInt) -> Self {
        todo!();
    }
}

impl From<&BigInt> for FeltIBig {
    fn from(value: &BigInt) -> Self {
        todo!();
    }
}
impl NewFelt for FeltIBig {
    fn new<T: Into<Self>>(value: T) -> Self {
        value.into()
    }
}

impl FeltOps for FeltIBig {
    fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        todo!();
    }

    fn iter_u64_digits(&self) -> U64Digits {
        todo!();
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        todo!();
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        todo!();
    }

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        todo!();
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        todo!();
    }

    fn to_str_radix(&self, radix: u32) -> String {
        todo!();
    }

    fn to_bigint(&self) -> BigInt {
        todo!();
    }

    fn to_biguint(&self) -> BigUint {
        todo!();
    }

    fn sqrt(&self) -> Self {
        todo!();
    }

    fn bits(&self) -> u64 {
        todo!();
    }
}

impl Bounded for FeltIBig {
    fn min_value() -> Self {
        Self::zero()
    }
    fn max_value() -> Self {
        Self::zero() - Self::one()
    }
}

impl Zero for FeltIBig {
    fn zero() -> Self {
        Self(UBig::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl One for FeltIBig {
    fn one() -> Self {
        Self(UBig::one())
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self.0.is_one()
    }
}

impl Pow<u32> for FeltIBig {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        self.0.pow(rhs as usize).into()
    }
}

impl<'a> Pow<u32> for &'a FeltIBig {
    type Output = FeltIBig;
    fn pow(self, rhs: u32) -> Self::Output {
        self.clone().pow(rhs)
    }
}

impl ToPrimitive for FeltIBig {
    fn to_u64(&self) -> Option<u64> {
        u64::try_from(&self.0).ok()
    }

    fn to_i64(&self) -> Option<i64> {
        i64::try_from(&self.0).ok()
    }

    fn to_usize(&self) -> Option<usize> {
        usize::try_from(&self.0).ok()
    }
}

impl FromPrimitive for FeltIBig {
    fn from_i64(n: i64) -> Option<Self> {
        Some(Self::from(n))
    }

    fn from_u64(n: u64) -> Option<Self> {
        Some(Self::from(n))
    }

    fn from_usize(n: usize) -> Option<Self> {
        Some(Self::from(n))
    }
}

impl Integer for FeltIBig {
    fn div_floor(&self, other: &Self) -> Self {
        todo!();
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        todo!();
    }

    fn divides(&self, other: &Self) -> bool {
        todo!();
    }

    fn gcd(&self, other: &Self) -> Self {
        todo!();
    }

    fn is_even(&self) -> bool {
        todo!();
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        todo!();
    }

    fn is_odd(&self) -> bool {
        todo!();
    }

    fn lcm(&self, other: &Self) -> Self {
        todo!();
    }

    fn mod_floor(&self, other: &Self) -> Self {
        todo!();
    }
}

impl Num for FeltIBig {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match IBig::from_str_radix(string, radix) {
            Ok(num) => Ok(Self::new(num)),
            Err(_) => Err(ParseFeltError),
        }
    }
}

impl Signed for FeltIBig {
    fn abs(&self) -> Self {
        self.clone()
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
            FeltIBig::zero()
        } else if self.is_positive() {
            FeltIBig::one()
        } else {
            FeltIBig::zero() - FeltIBig::one()
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero()
    }

    fn is_negative(&self) -> bool {
        self.is_zero()
    }
}

impl Neg for FeltIBig {
    type Output = FeltIBig;
    fn neg(self) -> Self::Output {
        todo!()
    }
    // TODO: ask if it makes sense to neg a unsigned value
}

impl Neg for &FeltIBig {
    type Output = FeltIBig;
    fn neg(self) -> Self::Output {
        self.clone().neg()
    }
}

impl Add for FeltIBig {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.0 += rhs.0;
        if &self.0 >= &*CAIRO_PRIME {
            self.0 -= &*CAIRO_PRIME
        }
        self
    }
}

impl Add<u32> for FeltIBig {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        todo!();
    }
}

impl Add<usize> for FeltIBig {
    type Output = Self;
    fn add(self, rhs: usize) -> Self {
        todo!();
    }
}

impl<'a> Add for &'a FeltIBig {
    type Output = FeltIBig;
    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = &self.0 + &rhs.0;
        if &sum >= &*CAIRO_PRIME {
            sum -= &*CAIRO_PRIME
        }
        FeltIBig(sum)
    }
}

impl<'a> Add<&'a FeltIBig> for FeltIBig {
    type Output = FeltIBig;

    fn add(self, rhs: &'a FeltIBig) -> Self::Output {
        &self + rhs
    }
}

impl<'a> Add<usize> for &'a FeltIBig {
    type Output = FeltIBig;
    fn add(self, rhs: usize) -> Self::Output {
        let mut sum = &self.0 + rhs;
        if &sum >= &*CAIRO_PRIME {
            sum -= &*CAIRO_PRIME
        }
        FeltIBig(sum)
    }
}

impl AddAssign for FeltIBig {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'a> AddAssign<&'a FeltIBig> for FeltIBig {
    fn add_assign(&mut self, rhs: &'a FeltIBig) {
        *self = &*self + rhs;
    }
}

impl Sum for FeltIBig {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Sub for FeltIBig {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.0);
        let result = left - right;
        Self(result.residue())
    }
}

impl Sub<u32> for FeltIBig {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        todo!();
    }
}

impl Sub<usize> for FeltIBig {
    type Output = Self;
    fn sub(self, rhs: usize) -> Self {
        todo!();
    }
}

impl<'a> Sub for &'a FeltIBig {
    type Output = FeltIBig;
    fn sub(self, rhs: Self) -> Self::Output {
        let left = CAIRO_MODULO_RING.from(&self.0);
        let right = CAIRO_MODULO_RING.from(&rhs.0);
        let result = left - right;
        FeltIBig(result.residue())
    }
}

impl<'a> Sub<&'a FeltIBig> for FeltIBig {
    type Output = FeltIBig;

    fn sub(self, rhs: &'a FeltIBig) -> Self::Output {
        &self - rhs
    }
}

impl<'a> Sub<u32> for &'a FeltIBig {
    type Output = FeltIBig;
    fn sub(self, rhs: u32) -> Self::Output {
        todo!();
    }
}

impl SubAssign for FeltIBig {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'a> SubAssign<&'a FeltIBig> for FeltIBig {
    fn sub_assign(&mut self, rhs: &'a FeltIBig) {
        *self = &*self - rhs;
    }
}

impl Sub<&FeltIBig> for usize {
    type Output = FeltIBig;
    fn sub(self, rhs: &FeltIBig) -> Self::Output {
        todo!();
    }
}
impl Mul for FeltIBig {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.0);
        let result = left * right;
        Self(result.residue())
    }
}

impl<'a> Mul for &'a FeltIBig {
    type Output = FeltIBig;
    fn mul(self, rhs: Self) -> Self::Output {
        let left = CAIRO_MODULO_RING.from(&self.0);
        let right = CAIRO_MODULO_RING.from(&rhs.0);
        let result = left * right;
        FeltIBig(result.residue())
    }
}

impl<'a> Mul<&'a FeltIBig> for FeltIBig {
    type Output = FeltIBig;

    fn mul(self, rhs: &'a FeltIBig) -> Self::Output {
        &self * rhs
    }
}

impl<'a> MulAssign<&'a FeltIBig> for FeltIBig {
    fn mul_assign(&mut self, rhs: &'a FeltIBig) {
        *self = &*self * rhs;
    }
}

impl Div for FeltIBig {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.0);
        let result = left / right;
        Self(result.residue())
    }
}

impl<'a> Div for &'a FeltIBig {
    type Output = FeltIBig;
    fn div(self, rhs: Self) -> Self::Output {
        let left = CAIRO_MODULO_RING.from(&self.0);
        let right = CAIRO_MODULO_RING.from(&rhs.0);
        let result = left / right;
        FeltIBig(result.residue())
    }
}

impl<'a> Div<&'a FeltIBig> for FeltIBig {
    type Output = FeltIBig;

    fn div(self, rhs: &'a FeltIBig) -> Self::Output {
        &self / rhs
    }
}

impl<'a> Div<FeltIBig> for &'a FeltIBig {
    type Output = FeltIBig;

    fn div(self, rhs: FeltIBig) -> Self::Output {
        self / &rhs
    }
}

impl<'a> DivAssign<&'a FeltIBig> for FeltIBig {
    fn div_assign(&mut self, rhs: &'a FeltIBig) {
        *self = &*self / rhs;
    }
}

impl DivAssign for FeltIBig {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.clone() / rhs;
    }
}

impl Shl<u32> for FeltIBig {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        let result = CAIRO_MODULO_RING.from(self.0 << other as usize);
        Self(result.residue())
    }
}

impl<'a> Shl<u32> for &'a FeltIBig {
    type Output = FeltIBig;
    fn shl(self, other: u32) -> Self::Output {
        let result = CAIRO_MODULO_RING.from(&self.0 << other as usize);
        FeltIBig(result.residue())
    }
}

impl Shl<usize> for FeltIBig {
    type Output = Self;
    fn shl(self, other: usize) -> Self::Output {
        let result = CAIRO_MODULO_RING.from(self.0 << other);
        Self(result.residue())
    }
}

impl<'a> Shl<usize> for &'a FeltIBig {
    type Output = FeltIBig;
    fn shl(self, other: usize) -> Self::Output {
        let result = CAIRO_MODULO_RING.from(&self.0 << other);
        FeltIBig(result.residue())
    }
}

impl Shr<u32> for FeltIBig {
    type Output = Self;
    fn shr(self, other: u32) -> Self::Output {
        let result = CAIRO_MODULO_RING.from(self.0 >> other as usize);
        Self(result.residue())
    }
}

impl ShrAssign<usize> for FeltIBig {
    fn shr_assign(&mut self, other: usize) {
        self.0 = CAIRO_MODULO_RING.from(&self.0 >> other as usize).residue();
    }
}

impl<'a> Shr<u32> for &'a FeltIBig {
    type Output = FeltIBig;
    fn shr(self, other: u32) -> Self::Output {
        let result = CAIRO_MODULO_RING.from(&self.0 >> other as usize);
        FeltIBig(result.residue())
    }
}

impl<'a> BitAnd for &'a FeltIBig {
    type Output = FeltIBig;
    fn bitand(self, rhs: Self) -> Self::Output {
        FeltIBig(&self.0 & &rhs.0)
    }
}

impl<'a> BitAnd<&'a FeltIBig> for FeltIBig {
    type Output = Self;
    fn bitand(self, rhs: &'a FeltIBig) -> Self::Output {
        FeltIBig(self.0 & &rhs.0)
    }
}

impl<'a> BitAnd<FeltIBig> for &'a FeltIBig {
    type Output = FeltIBig;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        FeltIBig(&self.0 & rhs.0)
    }
}

impl<'a> BitOr for &'a FeltIBig {
    type Output = FeltIBig;
    fn bitor(self, rhs: Self) -> Self::Output {
        FeltIBig(&self.0 | &rhs.0)
    }
}

impl<'a> BitXor for &'a FeltIBig {
    type Output = FeltIBig;
    fn bitxor(self, rhs: Self) -> Self::Output {
        FeltIBig(&self.0 ^ &rhs.0)
    }
}

impl<T: Into<FeltIBig>> Rem<T> for FeltIBig {
    type Output = Self;
    fn rem(self, rhs: T) -> Self {
        Self(self.0 % rhs.into().0)
    }
}

impl<T: Into<FeltIBig>> RemAssign<T> for FeltIBig {
    fn rem_assign(&mut self, rhs: T) {
        *self = self.clone() % rhs;
    }
}

impl FeltIBig {
    pub fn from_le_bytes(bytes: &[u8]) -> Self {
        FeltIBig::new(UBig::from_le_bytes(bytes))
    }
    pub fn modpow(&self, exponent: &FeltIBig, modulus: &FeltIBig) -> Self {
        //FeltIBig(self.0.modpow(&exponent.0, &modulus.0))
        todo!();
    }

    pub fn mod_floor(&self, other: &FeltIBig) -> Self {
        //FeltIBig(self.0.mod_floor(&other.0))
        todo!();
    }

    pub fn div_floor(&self, other: &FeltIBig) -> Self {
        //FeltIBig(self.0.div_floor(&other.0))
        todo!();
    }

    pub fn div_mod_floor(&self, other: &FeltIBig) -> (Self, Self) {
        //let (d, m) = self.0.div_mod_floor(&other.0);
        //(FeltIBig(d), FeltIBig(m))
        todo!();
    }

    pub fn iter_u64_digits(&self) -> U64Digits {
        //self.0.iter_u64_digits()
        todo!();
    }

    pub fn to_signed_bytes_le(&self) -> Vec<u8> {
        //self.0.to_signed_bytes_le()
        todo!();
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        //self.0.to_bytes_be().1
        todo!();
    }

    pub fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        IBig::from_str_radix(str::from_utf8(buf).ok()?, radix)
            .ok()
            .map(FeltIBig::new)
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        FeltIBig::new(UBig::from_be_bytes(bytes))
    }

    pub fn to_str_radix(&self, radix: u32) -> String {
        //self.0.to_str_radix(radix)
        todo!();
    }

    pub fn div_rem(&self, other: &FeltIBig) -> (FeltIBig, FeltIBig) {
        //div_rem(self, other)
        todo!();
    }

    pub fn to_bigint(&self) -> BigInt {
        /*if self.is_negative() {
            &self.0 - &*CAIRO_PRIME
        } else {
            self.0.clone()
        }*/
        todo!();
    }

    pub fn to_bigint_unsigned(&self) -> BigInt {
        //self.0.clone()
        todo!();
    }

    pub fn mul_inverse(&self) -> Self {
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
        Self((x.mod_floor(&CAIRO_PRIME) + &*CAIRO_PRIME).mod_floor(&CAIRO_PRIME))*/
        todo!();
    }

    pub fn sqrt(&self) -> Self {
        //FeltIBig(self.0.sqrt())
        todo!();
    }
}

impl fmt::Display for FeltIBig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_negative() {
            write!(f, "-{}", self.abs().0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl fmt::Debug for FeltIBig {
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
    use ibig::ubig;

    use super::*;

    #[test]
    fn create_feltibig() {
        let a = FeltIBig::from(1);
        assert_eq!(a.0, ubig!(1))
    }
}

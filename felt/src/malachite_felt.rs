use crate::{FeltOps, ParseFeltError, FIELD_HIGH, FIELD_LOW};
use lazy_static::lazy_static;
use malachite::{
    num::{
        arithmetic::traits::{ExtendedGcd, Mod, ModAdd, ModMul, ModPow, Parity},
        basic::traits::{One, Zero},
        conversion::traits::{ConvertibleFrom, FromStringBase, ToStringBase},
    },
    Integer, Natural,
};
use num_bigint::{BigInt, BigUint, U64Digits};
use num_integer::Integer as IntegerTrait;
use num_traits::{
    Bounded, FromPrimitive, Num, One as OneTrait, Pow, Signed, ToPrimitive, Zero as ZeroTrait,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    iter::Sum,
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign,
        Shl, Shr, ShrAssign, Sub, SubAssign,
    },
    str,
};

lazy_static! {
    pub static ref CAIRO_PRIME: Natural =
        (Natural::from(FIELD_HIGH) << 128) + Natural::from(FIELD_LOW);
    pub static ref CAIRO_PRIME_SIGNED: Integer =
        (Integer::from(FIELD_HIGH) << 128) + Integer::from(FIELD_LOW);
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FeltMalachite<const PH: u128, const PL: u128> {
    val: Natural,
}

macro_rules! from_integer {
    ($type:ty) => {
        impl<const FH: u128, const FL: u128> From<$type> for FeltMalachite<FH, FL> {
            fn from(value: $type) -> Self {
                Self {
                    val: value
                        .try_into()
                        .unwrap_or_else(|_| &*CAIRO_PRIME - &(-value as u128).into()),
                }
            }
        }
    };
}

macro_rules! from_unsigned {
    ($type:ty) => {
        impl<const FH: u128, const FL: u128> From<$type> for FeltMalachite<FH, FL> {
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
from_integer!(i128);
from_integer!(isize);

from_unsigned!(u8);
from_unsigned!(u16);
from_unsigned!(u32);
from_unsigned!(u64);
from_unsigned!(u128);
from_unsigned!(usize);

impl<const FH: u128, const FL: u128> From<Integer> for FeltMalachite<FH, FL> {
    fn from(value: Integer) -> Self {
        Self {
            val: match value {
                // Safe unwrap since converible from returns true
                _ if value < *CAIRO_PRIME && Natural::convertible_from(&value) => {
                    value.try_into().unwrap()
                }
                // Safe unwrap because CAIRO_PRIME_SIGNED is positive and the sign of mod_op is the
                // same as the second Integer used.
                _ => value.mod_op(&*CAIRO_PRIME_SIGNED).try_into().unwrap(),
            },
        }
    }
}

impl<const FH: u128, const FL: u128> From<Natural> for FeltMalachite<FH, FL> {
    fn from(value: Natural) -> Self {
        Self {
            val: match value {
                _ if value > *CAIRO_PRIME => value.mod_op(&*CAIRO_PRIME),
                _ if value == *CAIRO_PRIME => Natural::ZERO,
                _ => value,
            },
        }
    }
}

impl<const FH: u128, const FL: u128> From<&FeltMalachite<FH, FL>> for FeltMalachite<FH, FL> {
    fn from(value: &FeltMalachite<FH, FL>) -> Self {
        value.into()
    }
}

impl<const FH: u128, const FL: u128> From<BigUint> for FeltMalachite<FH, FL> {
    fn from(value: BigUint) -> Self {
        Self {
            val: Natural::from_string_base(10, &value.to_str_radix(10))
                .unwrap()
                .mod_op(&*CAIRO_PRIME),
        }
    }
}

impl<const FH: u128, const FL: u128> From<&BigUint> for FeltMalachite<FH, FL> {
    fn from(value: &BigUint) -> Self {
        Self {
            val: Natural::from_string_base(10, &value.to_str_radix(10))
                .unwrap()
                .mod_op(&*CAIRO_PRIME),
        }
    }
}

impl<const FH: u128, const FL: u128> From<BigInt> for FeltMalachite<FH, FL> {
    fn from(value: BigInt) -> Self {
        Self {
            val: Integer::from_string_base(10, &value.to_str_radix(10))
                .unwrap()
                .mod_op(&*CAIRO_PRIME_SIGNED)
                .try_into()
                .unwrap(),
        }
    }
}

impl<const FH: u128, const FL: u128> From<&BigInt> for FeltMalachite<FH, FL> {
    fn from(value: &BigInt) -> Self {
        Self {
            val: Integer::from_string_base(10, &value.to_str_radix(10))
                .unwrap()
                .mod_op(&*CAIRO_PRIME_SIGNED)
                .try_into()
                .unwrap(),
        }
    }
}

impl FeltOps for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn new<T: Into<Self>>(value: T) -> Self {
        value.into()
    }

    fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self {
            val: (&self.val).mod_pow(&exponent.val, &modulus.val),
        }
    }

    fn iter_u64_digits(&self) -> U64Digits {
        todo!(); //self.val.to_digits_asc(&(u64::MAX as u128 + 1)).into_iter().map(|n| u64::try_from(n).unwrap()).collect::<Vec<u64>>();
    }

    fn to_signed_bytes_le(&self) -> Vec<u8> {
        todo!();
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        todo!();
    }

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        Natural::from_string_base(radix as u8, str::from_utf8(buf).ok()?).map(FeltMalachite::new)
    }

    fn from_bytes_be(bytes: &[u8]) -> Self {
        todo!();
    }

    fn to_str_radix(&self, radix: u32) -> String {
        self.val.to_string_base(radix as u8)
    }

    fn to_bigint(&self) -> BigInt {
        todo!();
    }

    fn to_biguint(&self) -> BigUint {
        BigUint::from_str_radix(&self.val.to_string_base(10), 10).unwrap()
    }

    fn sqrt(&self) -> Self {
        todo!();
    }

    fn bits(&self) -> u64 {
        todo!();
    }
}

impl Bounded for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn min_value() -> Self {
        Self::zero()
    }
    fn max_value() -> Self {
        Self::zero() - Self::one()
    }
}

impl ZeroTrait for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn zero() -> Self {
        Self { val: Natural::ZERO }
    }

    fn is_zero(&self) -> bool {
        self.val == 0
    }
}

impl OneTrait for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn one() -> Self {
        Self { val: Natural::ONE }
    }

    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        self.val == 1
    }
}

impl Pow<u32> for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        Self {
            val: self.val.mod_pow(Natural::from(rhs), &*CAIRO_PRIME),
        }
    }
}

impl<'a> Pow<u32> for &'a FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;
    fn pow(self, rhs: u32) -> Self::Output {
        self.clone().pow(rhs)
    }
}

impl ToPrimitive for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn to_u64(&self) -> Option<u64> {
        u64::try_from(&self.val).ok()
    }

    fn to_i64(&self) -> Option<i64> {
        i64::try_from(&self.val).ok()
    }

    fn to_usize(&self) -> Option<usize> {
        usize::try_from(&self.val).ok()
    }
}

impl FromPrimitive for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
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

impl IntegerTrait for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn div_floor(&self, other: &Self) -> Self {
        Self {
            val: &self.val / &other.val,
        }
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
        self.val.odd()
    }

    fn lcm(&self, other: &Self) -> Self {
        todo!();
    }

    fn mod_floor(&self, other: &Self) -> Self {
        Self {
            val: (&self.val).mod_op(&other.val),
        }
    }
}

impl Num for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        match Natural::from_string_base(radix as u8, string) {
            Some(num) => Ok(Self::new(num)),
            None => Err(ParseFeltError),
        }
    }
}

impl Signed for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
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
            FeltMalachite::zero()
        } else if self.is_positive() {
            FeltMalachite::one()
        } else {
            FeltMalachite::zero() - FeltMalachite::one()
        }
    }

    fn is_positive(&self) -> bool {
        !self.is_zero()
    }

    fn is_negative(&self) -> bool {
        self.is_zero()
    }
}

impl Neg for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;
    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl Neg for &FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;
    fn neg(self) -> Self::Output {
        self.clone().neg()
    }
}

impl<const FH: u128, const FL: u128> Add for FeltMalachite<FH, FL> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.val += rhs.val;
        if &self.val >= &*CAIRO_PRIME {
            self.val -= &*CAIRO_PRIME
        }
        self
    }
}

impl<const FH: u128, const FL: u128> Add<u32> for FeltMalachite<FH, FL> {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        todo!();
    }
}

impl<const FH: u128, const FL: u128> Add<usize> for FeltMalachite<FH, FL> {
    type Output = Self;
    fn add(self, rhs: usize) -> Self {
        todo!();
    }
}

impl<'a, const FH: u128, const FL: u128> Add for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn add(self, rhs: Self) -> Self::Output {
        let mut sum = &self.val + &rhs.val;
        if sum >= *CAIRO_PRIME {
            sum -= &*CAIRO_PRIME;
        }
        FeltMalachite { val: sum }
    }
}

impl<'a, const FH: u128, const FL: u128> Add<&'a FeltMalachite<FH, FL>> for FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;

    fn add(self, rhs: &'a FeltMalachite<FH, FL>) -> Self::Output {
        &self + rhs
    }
}

impl<'a, const FH: u128, const FL: u128> Add<usize> for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn add(self, rhs: usize) -> Self::Output {
        Self::Output {
            val: (&self.val).mod_add(&rhs.into(), &*CAIRO_PRIME),
        }
    }
}

impl AddAssign for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

impl<'a> AddAssign<&'a FeltMalachite<FIELD_HIGH, FIELD_LOW>>
    for FeltMalachite<FIELD_HIGH, FIELD_LOW>
{
    fn add_assign(&mut self, rhs: &'a FeltMalachite<FIELD_HIGH, FIELD_LOW>) {
        *self = &*self + rhs;
    }
}

impl Sum for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl Sub for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self::Output {
        if self.val < rhs.val {
            self.val += &*CAIRO_PRIME;
        }
        self.val -= rhs.val;
        self
    }
}

impl Sub<u32> for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        todo!();
    }
}

impl Sub<usize> for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = Self;
    fn sub(self, rhs: usize) -> Self {
        todo!();
    }
}

impl<'a, const FH: u128, const FL: u128> Sub for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn sub(self, rhs: Self) -> Self::Output {
        FeltMalachite {
            val: if self.val < rhs.val {
                &*CAIRO_PRIME - (&rhs.val - &self.val)
            } else {
                &self.val - &rhs.val
            },
        }
    }
}

impl<'a> Sub<&'a FeltMalachite<FIELD_HIGH, FIELD_LOW>> for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;

    fn sub(self, rhs: &'a FeltMalachite<FIELD_HIGH, FIELD_LOW>) -> Self::Output {
        &self - rhs
    }
}

impl<'a> Sub<u32> for &'a FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;
    fn sub(self, rhs: u32) -> Self::Output {
        todo!();
    }
}

impl SubAssign for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

impl<'a> SubAssign<&'a FeltMalachite<FIELD_HIGH, FIELD_LOW>>
    for FeltMalachite<FIELD_HIGH, FIELD_LOW>
{
    fn sub_assign(&mut self, rhs: &'a FeltMalachite<FIELD_HIGH, FIELD_LOW>) {
        *self = &*self - rhs;
    }
}

impl Sub<&FeltMalachite<FIELD_HIGH, FIELD_LOW>> for usize {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;
    fn sub(self, rhs: &FeltMalachite<FIELD_HIGH, FIELD_LOW>) -> Self::Output {
        todo!();
    }
}

impl<const FH: u128, const FL: u128> Mul for FeltMalachite<FH, FL> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self {
            val: self.val.mod_mul(&rhs.val, &*CAIRO_PRIME),
        }
    }
}

impl<'a, const FH: u128, const FL: u128> Mul for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::Output {
            val: (&self.val).mod_mul(&rhs.val, &*CAIRO_PRIME),
        }
    }
}

impl<'a, const FH: u128, const FL: u128> Mul<&'a FeltMalachite<FH, FL>> for FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;

    fn mul(self, rhs: &'a FeltMalachite<FH, FL>) -> Self::Output {
        &self * rhs
    }
}

impl<'a, const FH: u128, const FL: u128> MulAssign<&'a FeltMalachite<FH, FL>>
    for FeltMalachite<FH, FL>
{
    fn mul_assign(&mut self, rhs: &'a FeltMalachite<FH, FL>) {
        *self = &*self * rhs;
    }
}

impl<const FH: u128, const FL: u128> Div for FeltMalachite<FH, FL> {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        let x: Self = rhs.val.extended_gcd(&*CAIRO_PRIME).1.into();
        self * x
    }
}

impl<'a, const FH: u128, const FL: u128> Div for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn div(self, rhs: Self) -> Self::Output {
        let x: Self::Output = (&rhs.val).extended_gcd(&*CAIRO_PRIME).1.into();
        self * &x
    }
}

impl<'a> Div<&'a FeltMalachite<FIELD_HIGH, FIELD_LOW>> for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;

    fn div(self, rhs: &'a FeltMalachite<FIELD_HIGH, FIELD_LOW>) -> Self::Output {
        &self / rhs
    }
}

impl<'a> Div<FeltMalachite<FIELD_HIGH, FIELD_LOW>> for &'a FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    type Output = FeltMalachite<FIELD_HIGH, FIELD_LOW>;

    fn div(self, rhs: FeltMalachite<FIELD_HIGH, FIELD_LOW>) -> Self::Output {
        self / &rhs
    }
}

impl<'a> DivAssign<&'a FeltMalachite<FIELD_HIGH, FIELD_LOW>>
    for FeltMalachite<FIELD_HIGH, FIELD_LOW>
{
    fn div_assign(&mut self, rhs: &'a FeltMalachite<FIELD_HIGH, FIELD_LOW>) {
        *self = &*self / rhs;
    }
}

impl DivAssign for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.clone() / rhs;
    }
}

impl<const FH: u128, const FL: u128> Shl<u32> for FeltMalachite<FH, FL> {
    type Output = Self;
    fn shl(self, other: u32) -> Self::Output {
        Self {
            val: (self.val << other).mod_op(&*CAIRO_PRIME),
        }
    }
}

impl<'a, const FH: u128, const FL: u128> Shl<u32> for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn shl(self, other: u32) -> Self::Output {
        Self::Output {
            val: (&self.val << other).mod_op(&*CAIRO_PRIME),
        }
    }
}

impl<const FH: u128, const FL: u128> Shl<usize> for FeltMalachite<FH, FL> {
    type Output = Self;
    fn shl(self, other: usize) -> Self {
        Self {
            val: (self.val << other).mod_op(&*CAIRO_PRIME),
        }
    }
}

impl<'a, const FH: u128, const FL: u128> Shl<usize> for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn shl(self, other: usize) -> Self::Output {
        Self::Output {
            val: (&self.val << other).mod_op(&*CAIRO_PRIME),
        }
    }
}

impl<const FH: u128, const FL: u128> Shr<u32> for FeltMalachite<FH, FL> {
    type Output = Self;
    fn shr(self, other: u32) -> Self {
        Self {
            val: self.val >> other,
        }
    }
}

impl<const FH: u128, const FL: u128> ShrAssign<usize> for FeltMalachite<FH, FL> {
    fn shr_assign(&mut self, other: usize) {
        self.val >>= other
    }
}

impl<'a, const FH: u128, const FL: u128> Shr<u32> for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn shr(self, other: u32) -> Self::Output {
        Self::Output {
            val: &self.val >> other,
        }
    }
}

impl<'a, const FH: u128, const FL: u128> BitAnd for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self::Output {
            val: &self.val & &rhs.val,
        }
    }
}

impl<'a, const FH: u128, const FL: u128> BitAnd<&'a FeltMalachite<FH, FL>>
    for FeltMalachite<FH, FL>
{
    type Output = Self;
    fn bitand(self, rhs: &'a FeltMalachite<FH, FL>) -> Self::Output {
        Self {
            val: self.val & &rhs.val,
        }
    }
}

impl<'a, const FH: u128, const FL: u128> BitAnd<FeltMalachite<FH, FL>>
    for &'a FeltMalachite<FH, FL>
{
    type Output = FeltMalachite<FH, FL>;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        Self::Output {
            val: &self.val & rhs.val,
        }
    }
}

impl<'a, const FH: u128, const FL: u128> BitOr for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self::Output {
            val: &self.val | &rhs.val,
        }
    }
}

impl<'a, const FH: u128, const FL: u128> BitXor for &'a FeltMalachite<FH, FL> {
    type Output = FeltMalachite<FH, FL>;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            val: &self.val ^ &rhs.val,
        }
    }
}

impl<T: Into<FeltMalachite<FIELD_HIGH, FIELD_LOW>>> Rem<T>
    for FeltMalachite<FIELD_HIGH, FIELD_LOW>
{
    type Output = Self;
    fn rem(self, _rhs: T) -> Self {
        FeltMalachite::zero()
    }
}

impl<T: Into<FeltMalachite<FIELD_HIGH, FIELD_LOW>>> RemAssign<T>
    for FeltMalachite<FIELD_HIGH, FIELD_LOW>
{
    fn rem_assign(&mut self, _rhs: T) {
        *self = FeltMalachite::zero();
    }
}

impl fmt::Display for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_negative() {
            write!(f, "-{}", self.abs().val)
        } else {
            write!(f, "{}", self.val)
        }
    }
}

impl fmt::Debug for FeltMalachite<FIELD_HIGH, FIELD_LOW> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.val)
    }
}

impl fmt::Display for ParseFeltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", ParseFeltError)
    }
}

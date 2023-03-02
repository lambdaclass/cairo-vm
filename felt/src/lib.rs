mod bigint_felt;

use bigint_felt::{FeltBigInt, FIELD_HIGH, FIELD_LOW};
use num_bigint::{BigInt, BigUint, U64Digits};
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

pub const PRIME_STR: &str = "0x800000000000011000000000000000000000000000000000000000000000001"; // in decimal, this is equal to 3618502788666131213697322783095070105623107215331596699973092056135872020481

pub(crate) trait FeltOps {
    fn new<T: Into<FeltBigInt<FIELD_HIGH, FIELD_LOW>>>(value: T) -> Self;

    fn modpow(
        &self,
        exponent: &FeltBigInt<FIELD_HIGH, FIELD_LOW>,
        modulus: &FeltBigInt<FIELD_HIGH, FIELD_LOW>,
    ) -> Self;

    fn iter_u64_digits(&self) -> U64Digits;

    fn to_signed_bytes_le(&self) -> Vec<u8>;

    fn to_bytes_be(&self) -> Vec<u8>;

    fn parse_bytes(buf: &[u8], radix: u32) -> Option<FeltBigInt<FIELD_HIGH, FIELD_LOW>>;

    fn from_bytes_be(bytes: &[u8]) -> Self;

    fn to_str_radix(&self, radix: u32) -> String;

    #[deprecated]
    /// Converts [`Felt`] into a [`BigInt`] number in the range: `(- FIELD / 2, FIELD / 2)`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::cairo_felt::Felt;
    /// # use num_bigint::BigInt;
    /// # use num_traits::Bounded;
    /// let positive = Felt::new(5);
    /// assert_eq!(positive.to_bigint(), Into::<num_bigint::BigInt>::into(5));
    ///
    /// let negative = Felt::max_value();
    /// assert_eq!(negative.to_bigint(), Into::<num_bigint::BigInt>::into(-1));
    /// ```
    fn to_bigint(&self) -> BigInt;

    #[deprecated]
    /// Converts [`Felt`] into a [`BigUint`] number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::cairo_felt::Felt;
    /// # use num_bigint::BigUint;
    /// # use num_traits::{Num, Bounded};
    /// let positive = Felt::new(5);
    /// assert_eq!(positive.to_biguint(), Into::<num_bigint::BigUint>::into(5_u32));
    ///
    /// let negative = Felt::max_value();
    /// assert_eq!(negative.to_biguint(), BigUint::from_str_radix("800000000000011000000000000000000000000000000000000000000000000", 16).unwrap());
    /// ```
    fn to_biguint(&self) -> BigUint;

    fn sqrt(&self) -> Self;

    fn bits(&self) -> u64;

    fn prime() -> BigUint;
}

#[macro_export]
macro_rules! felt_str {
    ($val: expr) => {
        felt::Felt::parse_bytes($val.as_bytes(), 10_u32).expect("Couldn't parse bytes")
    };
    ($val: expr, $opt: expr) => {
        felt::Felt::parse_bytes($val.as_bytes(), $opt as u32).expect("Couldn't parse bytes")
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseFeltError;

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Deserialize, Default, Serialize)]
pub struct Felt {
    value: FeltBigInt<FIELD_HIGH, FIELD_LOW>,
}

macro_rules! from_num {
    ($type:ty) => {
        impl From<$type> for Felt {
            fn from(value: $type) -> Self {
                Self {
                    value: value.into(),
                }
            }
        }
    };
}

from_num!(i8);
from_num!(i16);
from_num!(i32);
from_num!(i64);
from_num!(i128);
from_num!(isize);
from_num!(u8);
from_num!(u16);
from_num!(u32);
from_num!(u64);
from_num!(u128);
from_num!(usize);
from_num!(BigInt);
from_num!(&BigInt);
from_num!(BigUint);
from_num!(&BigUint);

impl Felt {
    pub fn new<T: Into<Felt>>(value: T) -> Self {
        value.into()
    }
    pub fn modpow(&self, exponent: &Felt, modulus: &Felt) -> Self {
        Self {
            value: self.value.modpow(&exponent.value, &modulus.value),
        }
    }
    pub fn iter_u64_digits(&self) -> U64Digits {
        self.value.iter_u64_digits()
    }
    pub fn to_signed_bytes_le(&self) -> Vec<u8> {
        self.value.to_signed_bytes_le()
    }
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }
    pub fn parse_bytes(buf: &[u8], radix: u32) -> Option<Self> {
        Some(Self {
            value: FeltBigInt::parse_bytes(buf, radix)?,
        })
    }
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self {
            value: FeltBigInt::from_bytes_be(bytes),
        }
    }
    pub fn to_str_radix(&self, radix: u32) -> String {
        self.value.to_str_radix(radix)
    }
    pub fn to_bigint(&self) -> BigInt {
        #[allow(deprecated)]
        self.value.to_bigint()
    }
    pub fn to_biguint(&self) -> BigUint {
        #[allow(deprecated)]
        self.value.to_biguint()
    }
    pub fn sqrt(&self) -> Self {
        Self {
            value: self.value.sqrt(),
        }
    }
    pub fn bits(&self) -> u64 {
        self.value.bits()
    }

    pub fn prime() -> BigUint {
        FeltBigInt::prime()
    }
}

impl Add for Felt {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            value: self.value + rhs.value,
        }
    }
}

impl<'a> Add for &'a Felt {
    type Output = Felt;
    fn add(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value + &rhs.value,
        }
    }
}

impl<'a> Add<&'a Felt> for Felt {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        Self::Output {
            value: self.value + &rhs.value,
        }
    }
}

impl Add<u32> for Felt {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        Self {
            value: self.value + rhs,
        }
    }
}

impl Add<usize> for Felt {
    type Output = Self;
    fn add(self, rhs: usize) -> Self {
        Self {
            value: self.value + rhs,
        }
    }
}

impl<'a> Add<usize> for &'a Felt {
    type Output = Felt;
    fn add(self, rhs: usize) -> Self::Output {
        Self::Output {
            value: &self.value + rhs,
        }
    }
}

impl AddAssign for Felt {
    fn add_assign(&mut self, rhs: Self) {
        self.value += rhs.value;
    }
}

impl<'a> AddAssign<&'a Felt> for Felt {
    fn add_assign(&mut self, rhs: &Self) {
        self.value += &rhs.value;
    }
}

impl Sum for Felt {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Felt::zero(), |mut acc, x| {
            acc += x;
            acc
        })
    }
}

impl Neg for Felt {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            value: self.value.neg(),
        }
    }
}

impl<'a> Neg for &'a Felt {
    type Output = Felt;
    fn neg(self) -> Self::Output {
        Self::Output {
            value: (&self.value).neg(),
        }
    }
}

impl Sub for Felt {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            value: self.value - rhs.value,
        }
    }
}

impl<'a> Sub for &'a Felt {
    type Output = Felt;
    fn sub(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value - &rhs.value,
        }
    }
}

impl<'a> Sub<&'a Felt> for Felt {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        Self {
            value: self.value - &rhs.value,
        }
    }
}

impl Sub<&Felt> for usize {
    type Output = Felt;
    fn sub(self, rhs: &Self::Output) -> Self::Output {
        Self::Output {
            value: self - &rhs.value,
        }
    }
}

impl SubAssign for Felt {
    fn sub_assign(&mut self, rhs: Self) {
        self.value -= rhs.value
    }
}

impl<'a> SubAssign<&'a Felt> for Felt {
    fn sub_assign(&mut self, rhs: &Self) {
        self.value -= &rhs.value;
    }
}

impl Sub<u32> for Felt {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        Self {
            value: self.value - rhs,
        }
    }
}

impl<'a> Sub<u32> for &'a Felt {
    type Output = Felt;
    fn sub(self, rhs: u32) -> Self::Output {
        Self::Output {
            value: &self.value - rhs,
        }
    }
}

impl Sub<usize> for Felt {
    type Output = Self;
    fn sub(self, rhs: usize) -> Self {
        Self {
            value: self.value - rhs,
        }
    }
}

impl Mul for Felt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self {
            value: self.value * rhs.value,
        }
    }
}

impl<'a> Mul for &'a Felt {
    type Output = Felt;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value * &rhs.value,
        }
    }
}

impl<'a> Mul<&'a Felt> for Felt {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self {
        Self {
            value: self.value * &rhs.value,
        }
    }
}

impl<'a> MulAssign<&'a Felt> for Felt {
    fn mul_assign(&mut self, rhs: &Self) {
        self.value *= &rhs.value;
    }
}

impl Pow<u32> for Felt {
    type Output = Self;
    fn pow(self, rhs: u32) -> Self {
        Self {
            value: self.value.pow(rhs),
        }
    }
}

impl<'a> Pow<u32> for &'a Felt {
    type Output = Felt;
    fn pow(self, rhs: u32) -> Self::Output {
        Self::Output {
            value: (&self.value).pow(rhs),
        }
    }
}

impl Div for Felt {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        Self {
            value: self.value / rhs.value,
        }
    }
}

impl<'a> Div for &'a Felt {
    type Output = Felt;
    fn div(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value / &rhs.value,
        }
    }
}

impl<'a> Div<Felt> for &'a Felt {
    type Output = Felt;
    fn div(self, rhs: Self::Output) -> Self::Output {
        Self::Output {
            value: &self.value / rhs.value,
        }
    }
}

impl Rem for Felt {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        Self {
            value: self.value % rhs.value,
        }
    }
}

impl<'a> Rem<&'a Felt> for Felt {
    type Output = Self;
    fn rem(self, rhs: &Self) -> Self {
        Self {
            value: self.value % &rhs.value,
        }
    }
}

impl Zero for Felt {
    fn zero() -> Self {
        Self {
            value: FeltBigInt::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
}

impl One for Felt {
    fn one() -> Self {
        Self {
            value: FeltBigInt::one(),
        }
    }

    fn is_one(&self) -> bool {
        self.value.is_one()
    }
}

impl Bounded for Felt {
    fn min_value() -> Self {
        Self {
            value: FeltBigInt::min_value(),
        }
    }

    fn max_value() -> Self {
        Self {
            value: FeltBigInt::max_value(),
        }
    }
}

impl Num for Felt {
    type FromStrRadixErr = ParseFeltError;
    fn from_str_radix(string: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        Ok(Self {
            value: FeltBigInt::from_str_radix(string, radix)?,
        })
    }
}

impl Integer for Felt {
    fn div_floor(&self, rhs: &Self) -> Self {
        Self {
            value: self.value.div_floor(&rhs.value),
        }
    }

    fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (div, rem) = self.value.div_rem(&other.value);
        (Self { value: div }, Self { value: rem })
    }

    fn divides(&self, other: &Self) -> bool {
        self.value.divides(&other.value)
    }

    fn gcd(&self, other: &Self) -> Self {
        Self {
            value: self.value.gcd(&other.value),
        }
    }

    fn is_even(&self) -> bool {
        self.value.is_even()
    }

    fn is_multiple_of(&self, other: &Self) -> bool {
        self.value.is_multiple_of(&other.value)
    }

    fn is_odd(&self) -> bool {
        self.value.is_odd()
    }

    fn lcm(&self, other: &Self) -> Self {
        Self {
            value: self.value.lcm(&other.value),
        }
    }

    fn mod_floor(&self, rhs: &Self) -> Self {
        Self {
            value: self.value.mod_floor(&rhs.value),
        }
    }
}

impl Signed for Felt {
    fn abs(&self) -> Self {
        Self {
            value: self.value.abs(),
        }
    }

    fn abs_sub(&self, other: &Self) -> Self {
        Self {
            value: self.value.abs_sub(&other.value),
        }
    }

    fn signum(&self) -> Self {
        Self {
            value: self.value.signum(),
        }
    }

    fn is_positive(&self) -> bool {
        self.value.is_positive()
    }

    fn is_negative(&self) -> bool {
        self.value.is_negative()
    }
}

impl Shl<u32> for Felt {
    type Output = Self;
    fn shl(self, rhs: u32) -> Self {
        Self {
            value: self.value << rhs,
        }
    }
}

impl<'a> Shl<u32> for &'a Felt {
    type Output = Felt;
    fn shl(self, rhs: u32) -> Self::Output {
        Self::Output {
            value: &self.value << rhs,
        }
    }
}

impl Shl<usize> for Felt {
    type Output = Self;
    fn shl(self, rhs: usize) -> Self {
        Self {
            value: self.value << rhs,
        }
    }
}

impl<'a> Shl<usize> for &'a Felt {
    type Output = Felt;
    fn shl(self, rhs: usize) -> Self::Output {
        Self::Output {
            value: &self.value << rhs,
        }
    }
}

impl Shr<u32> for Felt {
    type Output = Self;
    fn shr(self, rhs: u32) -> Self {
        Self {
            value: self.value >> rhs,
        }
    }
}

impl<'a> Shr<u32> for &'a Felt {
    type Output = Felt;
    fn shr(self, rhs: u32) -> Self::Output {
        Self::Output {
            value: &self.value >> rhs,
        }
    }
}

impl ShrAssign<usize> for Felt {
    fn shr_assign(&mut self, rhs: usize) {
        self.value >>= rhs
    }
}

impl<'a> BitAnd for &'a Felt {
    type Output = Felt;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value & &rhs.value,
        }
    }
}

impl<'a> BitAnd<&'a Felt> for Felt {
    type Output = Self;
    fn bitand(self, rhs: &Self) -> Self {
        Self {
            value: self.value & &rhs.value,
        }
    }
}

impl<'a> BitAnd<Felt> for &'a Felt {
    type Output = Felt;
    fn bitand(self, rhs: Self::Output) -> Self::Output {
        Self::Output {
            value: &self.value & rhs.value,
        }
    }
}

impl<'a> BitOr for &'a Felt {
    type Output = Felt;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value | &rhs.value,
        }
    }
}

impl<'a> BitXor for &'a Felt {
    type Output = Felt;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self::Output {
            value: &self.value ^ &rhs.value,
        }
    }
}

impl ToPrimitive for Felt {
    fn to_u64(&self) -> Option<u64> {
        self.value.to_u64()
    }

    fn to_i64(&self) -> Option<i64> {
        self.value.to_i64()
    }
}

impl FromPrimitive for Felt {
    fn from_u64(n: u64) -> Option<Self> {
        FeltBigInt::from_u64(n).map(|n| Self { value: n })
    }

    fn from_i64(n: i64) -> Option<Self> {
        FeltBigInt::from_i64(n).map(|n| Self { value: n })
    }
}

impl fmt::Display for Felt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl fmt::Debug for Felt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

macro_rules! assert_felt_methods {
    ($type:ty) => {
        const _: () = {
            fn assert_felt_ops<T: FeltOps>() {}
            fn assertion() {
                assert_felt_ops::<$type>();
            }
        };
    };
}

macro_rules! assert_felt_impl {
    ($type:ty) => {
        const _: () = {
            fn assert_add<T: Add>() {}
            fn assert_add_ref<'a, T: Add<&'a $type>>() {}
            fn assert_add_u32<T: Add<u32>>() {}
            fn assert_add_usize<T: Add<usize>>() {}
            fn assert_add_assign<T: AddAssign>() {}
            fn assert_add_assign_ref<'a, T: AddAssign<&'a $type>>() {}
            fn assert_sum<T: Sum<$type>>() {}
            fn assert_neg<T: Neg>() {}
            fn assert_sub<T: Sub>() {}
            fn assert_sub_ref<'a, T: Sub<&'a $type>>() {}
            fn assert_sub_assign<T: SubAssign>() {}
            fn assert_sub_assign_ref<'a, T: SubAssign<&'a $type>>() {}
            fn assert_sub_u32<T: Sub<u32>>() {}
            fn assert_sub_usize<T: Sub<usize>>() {}
            fn assert_mul<T: Mul>() {}
            fn assert_mul_ref<'a, T: Mul<&'a $type>>() {}
            fn assert_mul_assign_ref<'a, T: MulAssign<&'a $type>>() {}
            fn assert_pow<T: Pow<u32>>() {}
            fn assert_div<T: Div>() {}
            fn assert_ref_div<T: Div<$type>>() {}
            fn assert_rem<T: Rem>() {}
            fn assert_rem_ref<'a, T: Rem<&'a $type>>() {}
            fn assert_zero<T: Zero>() {}
            fn assert_one<T: One>() {}
            fn assert_bounded<T: Bounded>() {}
            fn assert_num<T: Num>() {}
            fn assert_integer<T: Integer>() {}
            fn assert_signed<T: Signed>() {}
            fn assert_shl_u32<T: Shl<u32>>() {}
            fn assert_shl_usize<T: Shl<usize>>() {}
            fn assert_shr_u32<T: Shr<u32>>() {}
            fn assert_shr_assign_usize<T: ShrAssign<usize>>() {}
            fn assert_bitand<T: BitAnd>() {}
            fn assert_bitand_ref<'a, T: BitAnd<&'a $type>>() {}
            fn assert_ref_bitand<T: BitAnd<$type>>() {}
            fn assert_bitor<T: BitOr>() {}
            fn assert_bitxor<T: BitXor>() {}
            fn assert_from_primitive<T: FromPrimitive>() {}
            fn assert_to_primitive<T: ToPrimitive>() {}
            fn assert_display<T: fmt::Display>() {}
            fn assert_debug<T: fmt::Debug>() {}

            #[allow(dead_code)]
            fn assert_all() {
                assert_add::<$type>();
                assert_add::<&$type>();
                assert_add_ref::<$type>();
                assert_add_u32::<$type>();
                assert_add_usize::<$type>();
                assert_add_usize::<&$type>();
                assert_add_assign::<$type>();
                assert_add_assign_ref::<$type>();
                assert_sum::<$type>();
                assert_neg::<$type>();
                assert_neg::<&$type>();
                assert_sub::<$type>();
                assert_sub::<&$type>();
                assert_sub_ref::<$type>();
                assert_sub_assign::<$type>();
                assert_sub_assign_ref::<$type>();
                assert_sub_u32::<$type>();
                assert_sub_u32::<&$type>();
                assert_sub_usize::<$type>();
                assert_mul::<$type>();
                assert_mul::<&$type>();
                assert_mul_ref::<$type>();
                assert_mul_assign_ref::<$type>();
                assert_pow::<$type>();
                assert_pow::<&$type>();
                assert_div::<$type>();
                assert_div::<&$type>();
                assert_ref_div::<&$type>();
                assert_rem::<$type>();
                assert_rem_ref::<$type>();
                assert_zero::<$type>();
                assert_one::<$type>();
                assert_bounded::<$type>();
                assert_num::<$type>();
                assert_integer::<$type>();
                assert_signed::<$type>();
                assert_shl_u32::<$type>();
                assert_shl_u32::<&$type>();
                assert_shl_usize::<$type>();
                assert_shl_usize::<&$type>();
                assert_shr_u32::<$type>();
                assert_shr_u32::<&$type>();
                assert_shr_assign_usize::<$type>();
                assert_bitand::<&$type>();
                assert_bitand_ref::<$type>();
                assert_ref_bitand::<&$type>();
                assert_bitor::<&$type>();
                assert_bitxor::<&$type>();
                assert_from_primitive::<$type>();
                assert_to_primitive::<$type>();
                assert_display::<$type>();
                assert_debug::<$type>();
            }
        };
    };
}

assert_felt_methods!(FeltBigInt<FIELD_HIGH, FIELD_LOW>);
assert_felt_impl!(FeltBigInt<FIELD_HIGH, FIELD_LOW>);
assert_felt_impl!(Felt);

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 felt values that are randomly generated each time tests are run, that a new felt doesn't fall outside the range [0, p].
        // In this and some of the following tests, The value of {x} can be either [0] or a very large number, in order to try to overflow the value of {p} and thus ensure the modular arithmetic is working correctly.
        fn new_in_range(ref x in "(0|[1-9][0-9]*)") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            prop_assert!(&x.to_biguint() < p);
        }

        #[test]
        // Property-based test that ensures, for 100 felt values that are randomly generated each time tests are run, that a felt created using Felt::from_bytes_be doesn't fall outside the range [0, p].
        // In this and some of the following tests, The value of {x} can be either [0] or a very large number, in order to try to overflow the value of {p} and thus ensure the modular arithmetic is working correctly.
        fn from_bytes_be_in_range(ref x in "(0|[1-9][0-9]*)") {
            let x = &Felt::from_bytes_be(x.as_bytes());
            let max_felt = &Felt::max_value();
            prop_assert!(x <= max_felt);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 felt values that are randomly generated each time tests are run, that the negative of a felt doesn't fall outside the range [0, p].
        fn neg_in_range(ref x in "(0|[1-9][0-9]*)") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let neg = -x;
            let as_uint = &neg.to_biguint();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            prop_assert!(as_uint < p);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 {x} and {y} values that are randomly generated each time tests are run, that a subtraction between two felts {x} and {y} and doesn't fall outside the range [0, p]. The values of {x} and {y} can be either [0] or a very large number.
        fn sub_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let sub = x - y;
            let as_uint = &sub.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 {x} and {y} values that are randomly generated each time tests are run, that a subtraction with assignment between two felts {x} and {y} and doesn't fall outside the range [0, p]. The values of {x} and {y} can be either [0] or a very large number.
        fn sub_assign_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let mut x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            x -= y;
            let as_uint = &x.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 {x} and {y} values that are randomly generated each time tests are run, that a multiplication between two felts {x} and {y} and doesn't fall outside the range [0, p]. The values of {x} and {y} can be either [0] or a very large number.
        fn mul_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let prod = x * y;
            let as_uint = &prod.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 pairs of {x} and {y} values that are randomly generated each time tests are run, that a multiplication with assignment between two felts {x} and {y} and doesn't fall outside the range [0, p]. The values of {x} and {y} can be either [0] or a very large number.
        fn mul_assign_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let mut x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            x *= y;
            let as_uint = &x.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 pairs of {x} and {y} values that are randomly generated each time tests are run, that the result of the division of {x} by {y} is the inverse multiplicative of {x} --that is, multiplying the result by {y} returns the original number {x}. The values of {x} and {y} can be either [0] or a very large number.
        fn div_is_mul_inv(ref x in "(0|[1-9][0-9]*)", ref y in "[1-9][0-9]*") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            prop_assume!(!y.is_zero());

            let q = x / y;
            let as_uint = &q.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
            prop_assert_eq!(&(q * y), x);
        }

        #[test]
        #[allow(deprecated)]
         // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the left by {shift_amount} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
        fn shift_left_in_range(ref value in "(0|[1-9][0-9]*)", ref shift_amount in "[0-9]{1,3}"){
            let value = Felt::parse_bytes(value.as_bytes(), 10).unwrap();
            let shift_amount:u32 = shift_amount.parse::<u32>().unwrap();
            let result = (value << shift_amount).to_biguint();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            prop_assert!(&result < p);
        }

        #[test]
        #[allow(deprecated)]
         // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the right by {shift_amount} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
        fn shift_right_in_range(ref value in "(0|[1-9][0-9]*)", ref shift_amount in "[0-9]{1,3}"){
            let value = Felt::parse_bytes(value.as_bytes(), 10).unwrap();
            let shift_amount:u32 = shift_amount.parse::<u32>().unwrap();
            let result = (value >> shift_amount).to_biguint();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            prop_assert!(&result < p);
        }

        #[test]
        #[allow(deprecated)]
        // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the right by {shift_amount} of bits (between 0 and 999), with assignment, returns a result that is inside of the range [0, p].
        // "With assignment" means that the result of the operation is autommatically assigned to the variable value, replacing its previous content.
        fn shift_right_assign_in_range(ref value in "(0|[1-9][0-9]*)", ref shift_amount in "[0-9]{1,3}"){
            let mut value = Felt::parse_bytes(value.as_bytes(), 10).unwrap();
            let shift_amount:usize = shift_amount.parse::<usize>().unwrap();
            let p = BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            value >>= shift_amount;
            prop_assert!(value.to_biguint() < p);
        }

        #[test]
        #[allow(deprecated)]
        // Property based test that ensures, for 100 pairs of values {x} and {y} generated at random each time tests are run, that performing a BitAnd operation between them returns a result that is inside of the range [0, p].
        fn bitand_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)"){
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let result = &x & &y;
            result.to_biguint();
            prop_assert!(result.to_biguint() < p);
        }

        #[test]
        #[allow(deprecated)]
        // Property based test that ensures, for 100 pairs of values {x} and {y} generated at random each time tests are run, that performing a BitOr operation between them returns a result that is inside of the range [0, p].
        fn bitor_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)"){
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let result = &x | &y;
            prop_assert!(result.to_biguint() < p);
        }

        #[test]
        #[allow(deprecated)]
        // Property based test that ensures, for 100 pairs of values {x} and {y} generated at random each time tests are run, that performing a BitXor operation between them returns a result that is inside of the range [0, p].
        fn bitxor_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)"){
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let result = &x ^ &y;
            prop_assert!(result.to_biguint() < p);
        }

        #[test]
        #[allow(deprecated)]
         // Property-based test that ensures, for 100 values {x} that are randomly generated each time tests are run, that raising {x} to the {y}th power returns a result that is inside of the range [0, p].
        fn pow_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "[0-9]{1,2}"){
            let base = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let exponent:u32 = y.parse()?;
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let result = Pow::pow(base, exponent);
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        // Property based test that ensures, for 100 pairs of values {x} and {y} generated at random each time tests are run, that performing a Sum operation between them returns a result that is inside of the range [0, p].
        fn sum_in_range(ref x in "[1-9][0-9]*", ref y in "[0-9][0-9]*"){
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let result = x + y;
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        // Property test to check that the remainder of a division between 100 pairs of values {x} and {y},generated at random each time tests are run, falls in the range [0, p]. x and y can either take the value of 0 or a large integer.
        // In Cairo, the result of x / y is defined to always satisfy the equation (x / y) * y == x, so the remainder is 0 most of the time.
        fn rem_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let result = x % y;
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

       #[test]
        // Property based test that ensures, for 100 Felts {x} generated at random each time tests are run, that converting them into the u64 type returns a result that is inside of the range [0, p].
       fn from_u64_and_to_u64_primitive(x in any::<u64>()) {
           let x_felt:Felt = Felt::from_u64(x).unwrap();
           let x_u64:u64 = Felt::to_u64(&x_felt).unwrap();

           prop_assert_eq!(x, x_u64);
        }

        #[test]
        // Property test to check that lcm(x, y) works. Since we're operating in a prime field, lcm
        // will just be the smaller number.
        fn lcm_doesnt_panic(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let lcm = x.lcm(&y);
            prop_assert!(lcm == std::cmp::max(x, y));
        }

        #[test]
        // Property test to check that is_multiple_of(x, y) works. Since we're operating in a prime field, is_multiple_of
        // will always be true
        fn is_multiple_of_doesnt_panic(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            prop_assert!(x.is_multiple_of(&y));
        }
    }

    #[test]
    // Checks that the result of adding two zeroes is zero
    fn sum_zeros_in_range() {
        let x = Felt::new(0);
        let y = Felt::new(0);
        let z = Felt::new(0);
        assert_eq!(x + y, z)
    }

    #[test]
    // Checks that the result of multiplying two zeroes is zero
    fn mul_zeros_in_range() {
        let x = Felt::new(0);
        let y = Felt::new(0);
        let z = Felt::new(0);
        assert_eq!(x * y, z)
    }

    #[test]
    // Checks that the result of perfforming a bit and operation between zeroes is zero
    fn bit_and_zeros_in_range() {
        let x = Felt::new(0);
        let y = Felt::new(0);
        let z = Felt::new(0);
        assert_eq!(&x & &y, z)
    }

    #[test]
    // Checks that the result of perfforming a bit or operation between zeroes is zero
    fn bit_or_zeros_in_range() {
        let x = Felt::new(0);
        let y = Felt::new(0);
        let z = Felt::new(0);
        assert_eq!(&x | &y, z)
    }

    #[test]
    // Checks that the result of perfforming a bit xor operation between zeroes is zero
    fn bit_xor_zeros_in_range() {
        let x = Felt::new(0);
        let y = Felt::new(0);
        let z = Felt::new(0);
        assert_eq!(&x ^ &y, z)
    }

    #[test]
    // Tests that the maximum value a Felt can take is equal to (prime - 1)
    fn upper_bound() {
        let prime = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
        let unit = BigUint::one();
        let felt_max_value = Felt::max_value().to_biguint();
        assert_eq!(prime - unit, felt_max_value)
    }

    #[test]
    // Tests that the minimum value a Felt can take is equal to zero.
    fn lower_bound() {
        let zero = BigUint::zero();
        let felt_min_value = Felt::min_value().to_biguint();
        assert_eq!(zero, felt_min_value)
    }

    #[test]
    fn zero_value() {
        let zero = BigUint::zero();
        let felt_zero = Felt::zero().to_biguint();
        assert_eq!(zero, felt_zero)
    }

    #[test]
    fn is_zero() {
        let felt_zero = Felt::zero();
        let felt_non_zero = Felt::new(3);
        assert!(felt_zero.is_zero());
        assert!(!felt_non_zero.is_zero())
    }
}

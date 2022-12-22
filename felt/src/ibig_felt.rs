use std::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shr, Sub, SubAssign,
};

#[allow(unused_imports)]
use ibig::{ibig, modular::ModuloRing, IBig, UBig};
use lazy_static::lazy_static;
use num_traits::{Bounded, FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use serde::Deserialize;

use crate::{Felt, NewFelt, NewStr, ParseFeltError, FIELD};

lazy_static! {
    pub static ref CAIRO_PRIME: UBig =
        UBig::from((UBig::from(FIELD.0) << 128) + UBig::from(FIELD.1));
    pub static ref CAIRO_MODULO_RING: ModuloRing =
        ModuloRing::new(&((UBig::from(FIELD.0) << 128) + UBig::from(FIELD.1)));
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Debug, Deserialize, Default)]
pub struct FeltIBig(UBig);

impl<T: Into<IBig>> From<T> for FeltIBig {
    fn from(value: T) -> Self {
        Self(CAIRO_MODULO_RING.from(value.into()).residue())
    }
}

impl NewFelt for FeltIBig {
    fn new<T: Into<Self>>(value: T) -> Self {
        value.into()
    }
}

impl NewStr for FeltIBig {
    fn new_str(num: &str, base: u8) -> Self {
        FeltIBig::from(IBig::from_str_radix(num, base as u32).expect("Couldn't parse bytes"))
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
        todo!()
    }

    fn to_i64(&self) -> Option<i64> {
        todo!()
    }

    fn to_usize(&self) -> Option<usize> {
        todo!()
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
        if self.0 <= other.0 {
            0i32.into()
        } else {
            self - other.clone()
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

impl<T: Into<FeltIBig>> Add<T> for FeltIBig {
    type Output = Self;
    fn add(self, rhs: T) -> Self {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.into().0);
        let result = left + right;
        Self(result.residue())
    }
}

impl<T: Into<FeltIBig>> AddAssign<T> for FeltIBig {
    fn add_assign(&mut self, rhs: T) {
        *self = self.clone() + rhs;
    }
}

impl<T: Into<FeltIBig>> Sub<T> for FeltIBig {
    type Output = Self;
    fn sub(self, rhs: T) -> Self::Output {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.into().0);
        let result = left - right;
        Self(result.residue())
    }
}

impl<T: Into<FeltIBig>> Sub<T> for &FeltIBig {
    type Output = FeltIBig;

    fn sub(self, rhs: T) -> Self::Output {
        self.clone() - rhs
    }
}

impl<T: Into<FeltIBig>> SubAssign<T> for FeltIBig {
    fn sub_assign(&mut self, rhs: T) {
        *self = self.clone() - rhs;
    }
}

impl<T: Into<FeltIBig>> Mul<T> for FeltIBig {
    type Output = Self;
    fn mul(self, rhs: T) -> Self {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.into().0);
        let result = left * right;
        Self(result.residue())
    }
}

impl<T: Into<FeltIBig>> MulAssign<T> for FeltIBig {
    fn mul_assign(&mut self, rhs: T) {
        *self = self.clone() * rhs;
    }
}

impl<T: Into<FeltIBig>> Div<T> for FeltIBig {
    type Output = Self;
    fn div(self, rhs: T) -> Self {
        let left = CAIRO_MODULO_RING.from(self.0);
        let right = CAIRO_MODULO_RING.from(rhs.into().0);
        let result = left / right;
        Self(result.residue())
    }
}

impl<T: Into<FeltIBig>> DivAssign<T> for FeltIBig {
    fn div_assign(&mut self, rhs: T) {
        *self = self.clone() / rhs;
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

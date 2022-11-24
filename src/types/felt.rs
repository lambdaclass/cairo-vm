use crate::{
    bigint,
    types::field::{Field, PRIME_HIGH, PRIME_LOW},
};
use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use std::{
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

pub type Felt = FeltBigInt<Field>;

lazy_static! {
    pub static ref CAIRO_PRIME: BigInt = (bigint!(PRIME_HIGH) << 128) + bigint!(PRIME_LOW);
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Clone, Debug)]
pub struct FeltBigInt<Field> {
    value: BigInt,
    phantom: PhantomData<Field>,
}

impl<Field> FeltBigInt<Field> {
    pub fn new(value: BigInt) -> Self {
        FeltBigInt {
            value,
            phantom: PhantomData,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
}

impl<Field> Add for FeltBigInt<Field> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        FeltBigInt {
            value: (self.value + rhs.value).mod_floor(&CAIRO_PRIME),
            phantom: PhantomData,
        }
    }
}

impl<Field> AddAssign for FeltBigInt<Field> {
    fn add_assign(&mut self, rhs: Self) {
        self.value = (self.value + rhs.value).mod_floor(&CAIRO_PRIME);
    }
}

impl<Field> Mul for FeltBigInt<Field> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        FeltBigInt {
            value: (self.value * rhs.value).mod_floor(&CAIRO_PRIME),
            phantom: PhantomData,
        }
    }
}

impl<Field> MulAssign for FeltBigInt<Field> {
    fn mul_assign(&mut self, rhs: Self) {
        self.value = (self.value * rhs.value).mod_floor(&CAIRO_PRIME);
    }
}

impl<Field> Sub for FeltBigInt<Field> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        FeltBigInt {
            value: (self.value - rhs.value).mod_floor(&CAIRO_PRIME),
            phantom: PhantomData,
        }
    }
}

impl<Field> SubAssign for FeltBigInt<Field> {
    fn sub_assign(&mut self, rhs: Self) {
        self.value = (self.value - rhs.value).mod_floor(&CAIRO_PRIME);
    }
}

use crate::{
    bigint,
    types::field::{Field, PRIME_HIGH, PRIME_LOW}
};
use std::{marker::PhantomData, ops::Add};
use num_bigint::BigInt;
use num_integer::Integer;
use lazy_static::lazy_static;


pub type Felt = FeltBigInt<Field>;

lazy_static! {
    pub static ref CAIRO_PRIME: BigInt = (bigint!(PRIME_HIGH) << 128) + bigint!(PRIME_LOW);
}

pub struct FeltBigInt<Field> {
    value: BigInt,
    phantom: PhantomData<Field>
}

impl<Field> FeltBigInt<Field> {
    pub fn new(value: BigInt) -> Self {
        FeltBigInt { value , phantom: PhantomData}
    }
}

impl<Field> Add for FeltBigInt<Field> {
    type Output = Self; 
    fn add(self, rhs: Self) -> Self {
        FeltBigInt {value : (self.value + rhs.value).mod_floor(&CAIRO_PRIME), phantom: PhantomData}
    }
}

mod bigint_felt;

use bigint_felt::FeltBigInt;
use num_integer::Integer;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use std::{
    cmp::Ordering,
    convert::Into,
    fmt,
    iter::Sum,
    ops::{Add, BitAnd, Div, Mul, MulAssign, Rem, Shl, Shr, ShrAssign, Sub},
};

pub type Felt = FeltBigInt;

pub const PRIME_STR: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
pub const FIELD: (u128, u128) = ((1 << 123) + (17 << 64), 1);

pub(crate) trait NewFelt {
    fn new<T: Into<Felt>>(value: T) -> Felt;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

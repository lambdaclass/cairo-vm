mod bigint_felt;

use std::convert::Into;

use bigint_felt::FeltBigInt;

pub type Felt = FeltBigInt;

pub use bigint_felt::div_rem;

pub const PRIME_STR: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
pub const FIELD: (u128, u128) = ((1 << 123) + (17 << 64), 1);

pub(crate) trait NewFelt {
    fn new<T: Into<Felt>>(value: T) -> Self;
}

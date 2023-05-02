use num_bigint::BigUint;
use num_traits::Zero;
use proptest::prelude::*;

use crate::{
    bigint_felt::{FeltBigInt, FIELD_HIGH, FIELD_LOW},
    Felt252,
};

pub(crate) fn any_felt_big_int<const PH: u128, const PL: u128>(
) -> impl Strategy<Value = FeltBigInt<PH, PL>> {
    (0..=PH)
        // turn range into `impl Strategy`
        .prop_map(|x| x)
        // choose second 128-bit limb capped by first one
        .prop_flat_map(|high| {
            let low = if high == PH {
                Strategy::sboxed((0..PL).prop_map(|x| x))
            } else {
                Strategy::sboxed(any::<u128>())
            };
            (Just(high), low)
        })
        // turn (u128, u128) into BigUint and then into FeltBigInt
        .prop_map(|(high, low)| {
            let biguint = (BigUint::from(high) << 128) + low;
            FeltBigInt::from(biguint)
        })
}

/// Returns a [`Strategy`] that generates any valid Felt252
pub fn any_felt252() -> impl Strategy<Value = Felt252> {
    any_felt_big_int::<FIELD_HIGH, FIELD_LOW>().prop_map(|value| Felt252 { value })
}

/// Returns a [`Strategy`] that generates any nonzero Felt252
pub fn nonzero_felt252() -> impl Strategy<Value = Felt252> {
    any_felt252().prop_filter("is zero", |x| !x.is_zero())
}

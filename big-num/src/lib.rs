mod bigint_num;

use bigint_num::BigIntNum;
use felt::{Felt, FeltOps};
use num_bigint::{BigInt, BigUint, U64Digits};
use num_integer::Integer;
use num_traits::{FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use std::{
    convert::Into,
    fmt::{Debug, Display},
    iter::Sum,
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Div, Mul, MulAssign, Neg, Rem, Shl, Shr, ShrAssign,
        Sub, SubAssign,
    },
};

pub type BigNum = BigIntNum;

pub trait BigNumOps {
    fn new<T: Into<BigNum>>(value: T) -> Self;
    fn modpow(&self, exponent: &BigNum, modulus: &BigNum) -> Self;
    fn iter_u64_digits(&self) -> U64Digits;
    fn to_signed_bytes_le(&self) -> Vec<u8>;
    fn to_bytes_be(&self) -> Vec<u8>;
    fn parse_bytes(buf: &[u8], radix: u32) -> Option<BigNum>;
    fn from_bytes_be(bytes: &[u8]) -> Self;
    fn to_str_radix(&self, radix: u32) -> String;
    fn to_bigint(&self) -> BigInt;
    fn to_biguint(&self) -> Option<BigUint>;
    fn sqrt(&self) -> Self;
    fn bits(&self) -> u64;
}

impl From<Felt> for BigNum {
    fn from(value: Felt) -> Self {
        Self::from_bytes_be(&value.to_bytes_be())
    }
}

impl From<&Felt> for BigNum {
    fn from(value: &Felt) -> Self {
        Self::from_bytes_be(&value.to_bytes_be())
    }
}

impl From<BigNum> for Felt {
    fn from(val: BigNum) -> Self {
        Felt::from_bytes_be(&val.to_bytes_be())
    }
}

impl From<&BigNum> for Felt {
    fn from(val: &BigNum) -> Self {
        Felt::from_bytes_be(&val.to_bytes_be())
    }
}

macro_rules! assert_bignum_impl {
    ($type:ty) => {
        const _: () = {
            fn assert_bignum_ops<T: BigNumOps>() {}
            fn assert_add<T: Add>() {}
            fn assert_add_ref<'a, T: Add<&'a $type>>() {}
            fn assert_add_u32<T: Add<u32>>() {}
            fn assert_add_usize<T: Add<usize>>() {}
            fn assert_add_ref_usize<T: Add<usize>>() {}
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
            fn assert_num<T: Num>() {}
            fn assert_integer<T: Integer>() {}
            fn assert_signed<T: Signed>() {}
            fn assert_shl_u32<T: Shl<u32>>() {}
            fn assert_shl_usize<T: Shl<usize>>() {}
            fn assert_shr_u32<T: Shr<u32>>() {}
            fn assert_shr_assign_usize<T: ShrAssign<usize>>() {}
            fn assert_bitand_ref<T: BitAnd>() {}
            fn assert_bitand<'a, T: BitAnd<&'a $type>>() {}
            fn assert_ref_bitand<T: BitAnd<$type>>() {}
            fn assert_bitor<T: BitOr>() {}
            fn assert_bitxor<T: BitXor>() {}
            fn assert_from_primitive<T: FromPrimitive>() {}
            fn assert_to_primitive<T: ToPrimitive>() {}
            fn assert_display<T: Display>() {}
            fn assert_debug<T: Debug>() {}

            // RFC 2056
            #[allow(dead_code)]
            fn assert_all() {
                assert_bignum_ops::<$type>();
                assert_add::<$type>();
                assert_add::<&$type>();
                assert_add_ref::<$type>();
                assert_add_u32::<$type>();
                assert_add_usize::<$type>();
                assert_add_ref_usize::<&$type>();
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
                assert_bitand_ref::<&$type>();
                assert_bitand::<$type>();
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

assert_bignum_impl!(BigNum);

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {

        #[test]
        // Property-based test that ensures, for 100 {x} and {y} values that are randomly generated each time tests are run, that the result of the division of {x} by {y} is the inverse multiplicative of {x} --that is, multiplying the result by {y} returns the original number {x}. The values of {x} and {y} can be either [0] or a very large number.
        fn div_is_mul_inv(ref x in "(0|[1-9][1-9]*)", ref y in "[1-9][1-9]*") {
            let x = &BigNum::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &BigNum::parse_bytes(y.as_bytes(), 10).unwrap();
            prop_assume!(!y.is_zero());
            prop_assume!(x.is_multiple_of(y));
            let q = x / y;
            prop_assert_eq!(&(q * y), x);
        }
    }
}

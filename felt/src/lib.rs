mod bigint_felt;

use bigint_felt::FeltBigInt;
use num_bigint::{BigInt, BigUint, U64Digits};
use num_integer::Integer;
use num_traits::{Bounded, FromPrimitive, Num, One, Pow, Signed, ToPrimitive, Zero};
use std::{
    convert::Into,
    fmt::{Debug, Display},
    iter::Sum,
    ops::{
        Add, AddAssign, BitAnd, BitOr, BitXor, Div, Mul, MulAssign, Neg, Rem, Shl, Shr, ShrAssign,
        Sub, SubAssign,
    },
};

pub type Felt = FeltBigInt;

pub const PRIME_STR: &str = "0x800000000000011000000000000000000000000000000000000000000000001";
pub const FIELD: (u128, u128) = ((1 << 123) + (17 << 64), 1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseFeltError;

pub trait NewFelt {
    fn new<T: Into<Felt>>(value: T) -> Self;
}

pub trait FeltOps {
    fn modpow(&self, exponent: &Felt, modulus: &Felt) -> Self;
    fn iter_u64_digits(&self) -> U64Digits;
    fn to_signed_bytes_le(&self) -> Vec<u8>;
    fn to_bytes_be(&self) -> Vec<u8>;
    fn parse_bytes(buf: &[u8], radix: u32) -> Option<Felt>;
    fn from_bytes_be(bytes: &[u8]) -> Self;
    fn to_str_radix(&self, radix: u32) -> String;
    fn to_bigint(&self) -> BigInt;
    fn to_biguint(&self) -> BigUint;
    fn sqrt(&self) -> Self;
    fn bits(&self) -> u64;
}

macro_rules! assert_felt_impl {
    ($type:ty) => {
        const _: () = {
            fn assert_new_felt<T: NewFelt>() {}
            fn assert_felt_ops<T: FeltOps>() {}
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
            fn assert_bounded<T: Bounded>() {}
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
                assert_new_felt::<$type>();
                assert_felt_ops::<$type>();
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

assert_felt_impl!(Felt);

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        // Property-based test that ensures, for 100 felt values that are randomly generated each time tests are run, that a new felt doesn't fall outside the range [0, p].
        // In this and some of the following tests, The value of {x} can be either [0] or a very large number, in order to try to overflow the value of {p} and thus ensure the modular arithmetic is working correctly.
        fn new_in_range(ref x in "(0|[1-9][0-9]*)") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            prop_assert!(&x.to_biguint() < p);
        }
        #[test]
        // Property-based test that ensures, for 100 felt values that are randomly generated each time tests are run, that the negative of a felt doesn't fall outside the range [0, p].
        fn neg_in_range(ref x in "(0|[1-9][0-9]*)") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let neg = -x;
            let as_uint = &neg.to_biguint();
            println!("x: {}, neg: {}", x, neg);
            prop_assert!(as_uint < p);
        }

        #[test]
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
        // Property-based test that ensures, for 100 {x} and {y} values that are randomly generated each time tests are run, that a multiplication with assignment between two felts {x} and {y} and doesn't fall outside the range [0, p]. The values of {x} and {y} can be either [0] or a very large number.
        fn mul_assign_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)") {
            let mut x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            x *= y;
            let as_uint = &x.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }

        #[test]
        // Property-based test that ensures, for 100 {x} and {y} values that are randomly generated each time tests are run, that the result of the division of {x} by {y} is the inverse multiplicative of {x} --that is, multiplying the result by {y} returns the original number {x}. The values of {x} and {y} can be either [0] or a very large number.
        fn div_is_mul_inv(ref x in "(0|[1-9][0-9]*)", ref y in "[1-9][0-9]*") {
            let x = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = &Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            prop_assume!(!y.is_zero());
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let q = x / y;
            let as_uint = &q.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
            prop_assert_eq!(&(q * y), x);
        }

        #[test]
         // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the left by {shift_amount} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
        fn shift_left_in_range(ref value in "(0|[1-9][0-9]*)", ref shift_amount in "[0-9]{1,3}"){
            let value = Felt::parse_bytes(value.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let shift_amount:u32 = shift_amount.parse::<u32>().unwrap();
            let result = (value << shift_amount).to_biguint();
            prop_assert!(&result < p);
        }

        #[test]
         // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the right by {shift_amount} of bits (between 0 and 999) returns a result that is inside of the range [0, p].
        fn shift_right_in_range(ref value in "(0|[1-9][0-9]*)", ref shift_amount in "[0-9]{1,3}"){
            let value = Felt::parse_bytes(value.as_bytes(), 10).unwrap();
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let shift_amount:u32 = shift_amount.parse::<u32>().unwrap();
            let result = (value >> shift_amount).to_biguint();
            prop_assert!(&result < p);
        }

        #[test]
        // Property-based test that ensures, for 100 {value}s that are randomly generated each time tests are run, that performing a bit shift to the right by {shift_amount} of bits (between 0 and 999), with assignment, returns a result that is inside of the range [0, p].
        // "With assignment" means that the result of the operation is autommatically assigned to the variable value, replacing its previous content.
        fn shift_right_assign_in_range(ref value in "(0|[1-9][0-9]*)", ref shift_amount in "[0-9]{1,3}"){
            let mut value = Felt::parse_bytes(value.as_bytes(), 10).unwrap();
            let p = FeltBigInt::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let shift_amount:usize = shift_amount.parse::<usize>().unwrap();
            value >>= shift_amount;
            value.to_biguint();
            prop_assert!(value < p);
        }

        #[test]
        // Property based test that ensures, for a pair of 100 values {x} and {y} generated at random each time tests are run, that performing a BitAnd operation between them returns a result that is inside of the range [0, p].
        fn bitand_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)"){
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = FeltBigInt::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let result = &x & &y;
            result.to_biguint();
            prop_assert!(result < p);
        }

        #[test]
        // Property based test that ensures, for a pair of 100 values {x} and {y} generated at random each time tests are run, that performing a BitOr operation between them returns a result that is inside of the range [0, p].
        fn bitor_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)"){
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = FeltBigInt::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let result = &x | &y;
            println!("x: {}, y: {}, result: {}", x, y, result);
            result.to_biguint();
            prop_assert!(result < p);
        }

        #[test]
        // Property based test that ensures, for a pair of 100 values {x} and {y} generated at random each time tests are run, that performing a BitXor operation between them returns a result that is inside of the range [0, p].
        fn bitxor_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "(0|[1-9][0-9]*)"){
            let x = Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let y = Felt::parse_bytes(y.as_bytes(), 10).unwrap();
            let p = FeltBigInt::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();
            let result = &x ^ &y;
            println!("x: {}, y: {}, result: {}", x, y, result);
            result.to_biguint();
            prop_assert!(result < p);
        }

        #[test]
         // Property-based test that ensures, for 100 values {x} that are randomly generated each time tests are run, that raising {x} to the {y}th power returns a result that is inside of the range [0, p].
        fn pow_in_range(ref x in "(0|[1-9][0-9]*)", ref y in "[0-9]{1,2}"){
            let base = &Felt::parse_bytes(x.as_bytes(), 10).unwrap();
            let exponent:u32 = y.parse()?;
            let p = &BigUint::parse_bytes(PRIME_STR[2..].as_bytes(), 16).unwrap();

            let result = Pow::pow(base, exponent);
            let as_uint = &result.to_biguint();
            prop_assert!(as_uint < p, "{}", as_uint);
        }
    }
}

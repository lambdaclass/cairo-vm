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

macro_rules! assert_felt_impl {
    ($type:ty) => {
        const _: () = {
            fn assert_add<T: std::ops::Add<$type, Output = $type>>() {}
            fn assert_add_ref<'a, T: std::ops::Add<&'a $type, Output = $type>>() {}
            fn assert_add_assign<'a, T: std::ops::AddAssign<&'a $type>>() {}
            fn assert_sub<T: std::ops::Sub<$type, Output = $type>>() {}
            fn assert_sub_ref<'a, T: std::ops::Sub<&'a $type, Output = $type>>() {}
            fn assert_sub_assign<'a, T: std::ops::SubAssign<&'a $type>>() {}
            fn assert_mul<T: std::ops::Mul<$type, Output = $type>>() {}
            fn assert_mul_ref<'a, T: std::ops::Mul<&'a $type, Output = $type>>() {}
            fn assert_mul_assign<'a, T: std::ops::MulAssign<&'a $type>>() {}
            fn assert_bitand<T: std::ops::BitAnd<$type, Output = $type>>() {}
            fn assert_bitor<T: std::ops::BitOr<$type, Output = $type>>() {}
            fn assert_bitxor<T: std::ops::BitXor<$type, Output = $type>>() {}
            fn assert_div<T: std::ops::Div<$type, Output = $type>>() {}
            fn assert_div_assign<T: std::ops::DivAssign<$type>>() {}
            fn assert_neg<T: std::ops::Neg>() {}

            fn assert_sum<T: std::iter::Sum<$type>>() {}

            fn assert_zero<T: num_traits::Zero>() {}
            fn assert_one<T: num_traits::One>() {}
            fn assert_bounded<T: num_traits::Bounded>() {}
            fn assert_from_primitive<T: num_traits::FromPrimitive>() {}
            fn assert_to_primitive<T: num_traits::ToPrimitive>() {}

            // RFC 2056
            #[allow(dead_code)]
            fn assert_all() {
                assert_add::<$type>();
                assert_add_ref::<$type>();
                assert_add_assign::<$type>();
                assert_sub::<$type>();
                assert_sub_ref::<$type>();
                assert_sub_assign::<$type>();
                assert_mul::<$type>();
                assert_mul_ref::<$type>();
                assert_mul_assign::<$type>();
                assert_bitand::<$type>();
                assert_bitor::<$type>();
                assert_bitxor::<$type>();
                assert_div::<$type>();
                assert_div_assign::<$type>();
                assert_neg::<$type>();

                assert_sum::<$type>();

                assert_zero::<$type>();
                assert_one::<$type>();
                assert_bounded::<$type>();
                assert_from_primitive::<$type>();
                assert_to_primitive::<$type>();
            }
        };
    };
}

assert_felt_impl!(Felt);

#[contract]
mod TestUint256DivMod {
    use zeroable::IsZeroResult;
    use zeroable::NonZeroIntoImpl;
    use zeroable::NonZero;
    use core::traits::Into;
    use traits::TryInto;
    
    #[external]
    fn test_uint256_div_mod(a:u128, b:u128) -> felt252 {
        let a = as_u256(8_u128,0);
        let b = as_u256(2_u128,0);
        let b = integer::u256_as_non_zero(b);

        let (res, _) = integer::u256_safe_divmod(a, b);

        res.low.into()
    }

    #[internal]
    fn as_u256(a: u128, b: u128) -> u256{
        u256{
            low: a,
            high: b
        }
    }
}
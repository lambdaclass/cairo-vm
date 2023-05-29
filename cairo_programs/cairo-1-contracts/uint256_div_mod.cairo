#[contract]
mod TestUint256DivMod {
    use zeroable::IsZeroResult;
    use zeroable::NonZeroIntoImpl;
    use zeroable::NonZero;
    use core::traits::Into;
    use traits::TryInto;
    use integer::BoundedInt;
    
    #[external]
    fn test_uint256_div_mod_max() {
        let a = BoundedInt::max();

        let b = as_u256(1_u128, 0);
        let b = integer::u256_as_non_zero(b);

        let (res, _) = integer::u256_safe_divmod(a, b);

        assert(a==res, 'div failed')
    }


    #[external]
    fn test_uint256_div_mod(a:u128, b:u128) -> felt252 {
        let a = as_u256(a, 0);
        let b = as_u256(b, 0);

        let b = integer::u256_as_non_zero(b);

        let (res, _) = integer::u256_safe_divmod(a, b);

        return res.low.into();
    }

    #[internal]
    fn as_u256(a: u128, b: u128) -> u256{
        u256{
            low: a,
            high: b
        }
    }
}
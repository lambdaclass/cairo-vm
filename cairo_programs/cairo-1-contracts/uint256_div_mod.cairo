#[contract]
mod TestUint256DivMod {
    use zeroable::IsZeroResult;
    use zeroable::NonZeroIntoImpl;
    use zeroable::NonZero;

    #[external]
    fn test_uint256_div_mod(a: u256, b: u256) -> u256 {
        a / b
    }
}

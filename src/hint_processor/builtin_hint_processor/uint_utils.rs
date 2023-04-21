use felt::Felt252;
use num_bigint::BigUint;

pub(crate) fn split<const T: usize>(num: &BigUint, num_bits_shift: u32) -> [BigUint; T] {
    let mut num = num.clone();
    let bitmask = &BigUint::from(u128::MAX);
    [0; T].map(|_| {
        let a = &num & bitmask;
        num >>= num_bits_shift;
        a
    })
}

pub(crate) fn pack<const T: usize>(
    limbs: [impl AsRef<Felt252>; T],
    num_bits_shift: usize,
) -> BigUint {
    limbs
        .into_iter()
        .enumerate()
        .map(|(i, limb)| limb.as_ref().to_biguint() << (i * num_bits_shift))
        .sum()
}

use felt::Felt252;
use num_bigint::BigUint;
use num_traits::One;

pub(crate) fn split<const T: usize>(num: &BigUint, num_bits_shift: u32) -> [BigUint; T] {
    let mut num = num.clone();
    [0; T].map(|_| {
        let a = &num & &((BigUint::one() << num_bits_shift) - 1_u32);
        num = &num >> num_bits_shift;
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

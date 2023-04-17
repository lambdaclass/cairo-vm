use felt::Felt252;
use num_traits::Zero;

/*
def pack_512(d0, d1,d2,d3, num_bits_shift: int) -> int:
    limbs = (d0, d1, d2, d3)
    return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

*/
#[allow(dead_code)]
fn pack_512(d0: Felt252, d1: Felt252, d2: Felt252, d3: Felt252, num_bits_shift: Felt252) {
    let mut result = Felt252::zero();
    let mut counter = 0;
    for x in [d0, d1, d2, d3] {
        let t = counter * num_bits_shift;
        result = result + x >> (num_bits_shift);
        counter += 1;
    }
}

use core::ops::Shl;

use felt::Felt252;
use num_bigint::BigUint;
use num_traits::One;

use crate::stdlib::{collections::HashMap, prelude::*};
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

use super::secp::bigint_utils::BigInt3;

fn split<const T: usize>(num: &Felt252, num_bits_shift: u32) -> [Felt252; T] {
    let mut num = num.clone();
    [0; T].map(|_| {
        let a = &num & &((Felt252::one() << num_bits_shift) - 1_u32);
        num = &num >> num_bits_shift;
        a
    })
}

fn pack(num: BigInt3, num_bits_shift: usize) -> BigUint {
    let limbs = vec![num.d0, num.d1, num.d2];
    #[allow(deprecated)]
    limbs
        .into_iter()
        .enumerate()
        .map(|(idx, value)| value.to_biguint().shl(idx * num_bits_shift))
        .sum()
}

// Notes: Hints in this lib use the type Uint348, which is equal to common lib's BigInt3
/* Implements Hint:
       %{
           def split(num: int, num_bits_shift: int, length: int):
               a = []
               for _ in range(length):
                   a.append( num & ((1 << num_bits_shift) - 1) )
                   num = num >> num_bits_shift
               return tuple(a)

           def pack(z, num_bits_shift: int) -> int:
               limbs = (z.d0, z.d1, z.d2)
               return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

           a = pack(ids.a, num_bits_shift = 128)
           div = pack(ids.div, num_bits_shift = 128)
           quotient, remainder = divmod(a, div)

           quotient_split = split(quotient, num_bits_shift=128, length=3)
           assert len(quotient_split) == 3

           ids.quotient.d0 = quotient_split[0]
           ids.quotient.d1 = quotient_split[1]
           ids.quotient.d2 = quotient_split[2]

           remainder_split = split(remainder, num_bits_shift=128, length=3)
           ids.remainder.d0 = remainder_split[0]
           ids.remainder.d1 = remainder_split[1]
           ids.remainder.d2 = remainder_split[2]
       %}
*/
pub fn uint348_unsigned_div_rem(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    Ok(())
}

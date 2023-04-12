use core::ops::Shl;
use felt::Felt252;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

use crate::stdlib::{collections::HashMap, prelude::*};
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

use super::hint_utils::get_relocatable_from_var_name;
use super::secp::bigint_utils::BigInt3;
// Notes: Hints in this lib use the type Uint384, which is equal to common lib's BigInt3

fn split<const T: usize>(num: &BigUint, num_bits_shift: u32) -> [BigUint; T] {
    let mut num = num.clone();
    [0; T].map(|_| {
        let a = &num & &((BigUint::one() << num_bits_shift) - 1_u32);
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
pub fn uint384_unsigned_div_rem(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let a = pack(BigInt3::from_var_name("a", vm, ids_data, ap_tracking)?, 128);
    let div = pack(
        BigInt3::from_var_name("div", vm, ids_data, ap_tracking)?,
        128,
    );
    let quotient_addr = get_relocatable_from_var_name("quotient", vm, ids_data, ap_tracking)?;
    let remainder_addr = get_relocatable_from_var_name("remainder", vm, ids_data, ap_tracking)?;
    let (quotient, remainder) = a.div_mod_floor(&div);
    let quotient_split = split::<3>(&quotient, 128);
    for (i, quotient_split) in quotient_split.iter().enumerate() {
        vm.insert_value((quotient_addr + i)?, Felt252::from(quotient_split))?;
    }
    let remainder_split = split::<3>(&remainder, 128);
    for (i, remainder_split) in remainder_split.iter().enumerate() {
        vm.insert_value((remainder_addr + i)?, Felt252::from(remainder_split))?;
    }
    Ok(())
}

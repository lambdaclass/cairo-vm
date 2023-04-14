use felt::Felt252;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::math_utils::{is_quad_residue, sqrt_prime_power};
use crate::serde::deserialize_program::ApTracking;
use crate::stdlib::{collections::HashMap, prelude::*};
use crate::vm::errors::hint_errors::HintError;
use crate::{
    hint_processor::hint_processor_definition::HintReference, vm::vm_core::VirtualMachine,
};

use super::hint_utils::{get_relocatable_from_var_name, insert_value_from_var_name};
use super::secp::bigint_utils::BigInt3;
use super::uint384::{pack, split};
/* Implements Hint:
      %{
           from starkware.python.math_utils import is_quad_residue, sqrt

           def split(num: int, num_bits_shift: int = 128, length: int = 3):
               a = []
               for _ in range(length):
                   a.append( num & ((1 << num_bits_shift) - 1) )
                   num = num >> num_bits_shift
               return tuple(a)

           def pack(z, num_bits_shift: int = 128) -> int:
               limbs = (z.d0, z.d1, z.d2)
               return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))


           generator = pack(ids.generator)
           x = pack(ids.x)
           p = pack(ids.p)

           success_x = is_quad_residue(x, p)
           root_x = sqrt(x, p) if success_x else None

           success_gx = is_quad_residue(generator*x, p)
           root_gx = sqrt(generator*x, p) if success_gx else None

           # Check that one is 0 and the other is 1
           if x != 0:
               assert success_x + success_gx ==1

           # `None` means that no root was found, but we need to transform these into a felt no matter what
           if root_x == None:
               root_x = 0
           if root_gx == None:
               root_gx = 0
           ids.success_x = int(success_x)
           split_root_x = split(root_x)
           split_root_gx = split(root_gx)
           ids.sqrt_x.d0 = split_root_x[0]
           ids.sqrt_x.d1 = split_root_x[1]
           ids.sqrt_x.d2 = split_root_x[2]
           ids.sqrt_gx.d0 = split_root_gx[0]
           ids.sqrt_gx.d1 = split_root_gx[1]
           ids.sqrt_gx.d2 = split_root_gx[2]
       %}
*/
pub fn get_square_root(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let sqrt_x_addr = get_relocatable_from_var_name("sqrt_x", vm, ids_data, ap_tracking)?;
    let sqrt_gx_addr = get_relocatable_from_var_name("sqrt_gx", vm, ids_data, ap_tracking)?;
    let generator = pack(
        BigInt3::from_var_name("generator", vm, ids_data, ap_tracking)?,
        128,
    );
    let x = pack(BigInt3::from_var_name("x", vm, ids_data, ap_tracking)?, 128);
    let p = pack(BigInt3::from_var_name("p", vm, ids_data, ap_tracking)?, 128);
    let success_x = is_quad_residue(&x, &p)?;
    //TODO use sqrt algorithm from sympy
    let root_x = if success_x {
        sqrt_prime_power(&x, &p).unwrap_or_default()
    } else {
        BigUint::zero()
    };

    let gx = generator * &x;
    let success_gx = is_quad_residue(&gx, &p)?;
    //TODO use sqrt algorithm from sympy
    let root_gx = if success_gx {
        sqrt_prime_power(&gx, &p).unwrap_or_default()
    } else {
        BigUint::zero()
    };

    if !&x.is_zero() {
        if !(success_x as u8 + success_gx as u8).is_one() {
            return Err(HintError::AssertionFailed(String::from(
                "assert success_x + success_gx ==1",
            )));
        }
    }
    insert_value_from_var_name(
        "success_x",
        Felt252::from(success_x as u8),
        vm,
        ids_data,
        ap_tracking,
    )?;
    let split_root_x = split::<3>(&root_x, 128);
    for (i, root_x) in split_root_x.iter().enumerate() {
        vm.insert_value((sqrt_x_addr + i)?, Felt252::from(root_x))?;
    }
    let split_root_gx = split::<3>(&root_gx, 128);
    for (i, root_gx) in split_root_gx.iter().enumerate() {
        vm.insert_value((sqrt_gx_addr + i)?, Felt252::from(root_gx))?;
    }

    Ok(())
}

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

    let root_x = if success_x {
        sqrt_prime_power(&x, &p).unwrap_or_default()
    } else {
        BigUint::zero()
    };

    let gx = generator * &x;
    let success_gx = is_quad_residue(&gx, &p)?;

    let root_gx = if success_gx {
        sqrt_prime_power(&gx, &p).unwrap_or_default()
    } else {
        BigUint::zero()
    };

    if !&x.is_zero() && !(success_x as u8 + success_gx as u8).is_one() {
        return Err(HintError::AssertionFailed(String::from(
            "assert success_x + success_gx ==1",
        )));
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hint_processor::builtin_hint_processor::hint_code;
    use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
    use crate::{
        any_box,
        hint_processor::{
            builtin_hint_processor::builtin_hint_processor_definition::{
                BuiltinHintProcessor, HintProcessorData,
            },
            hint_processor_definition::HintProcessor,
        },
        types::{exec_scope::ExecutionScopes, relocatable::MaybeRelocatable},
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, runners::builtin_runner::RangeCheckBuiltinRunner,
            vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_get_square_ok_goldilocks_prime() {
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 14;
        //Create hint_data
        let ids_data = non_continuous_ids_data![
            ("p", -14),
            ("x", -11),
            ("generator", -8),
            ("sqrt_x", -5),
            ("sqrt_gx", -2),
            ("success_x", 1)
        ];
        //Insert ids into memory
        vm.segments = segments![
            //p
            ((1, 0), 18446744069414584321),
            ((1, 1), 0),
            ((1, 2), 0),
            //x
            ((1, 3), 25),
            ((1, 4), 0),
            ((1, 5), 0),
            //generator
            ((1, 6), 7),
            ((1, 7), 0),
            ((1, 8), 0)
        ];
        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code::GET_SQUARE_ROOT), Ok(()));
        //Check hint memory inserts
        check_memory![
            vm.segments.memory,
            // sqrt_x
            ((1, 9), 5),
            ((1, 10), 0),
            ((1, 11), 0),
            // sqrt_gx
            ((1, 12), 0),
            ((1, 13), 0),
            ((1, 14), 0),
            // success_x
            ((1, 15), 1)
        ];
    }
}

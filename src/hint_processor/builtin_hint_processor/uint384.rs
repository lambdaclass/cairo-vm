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

use super::hint_utils::{
    get_integer_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name,
};
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

/* Implements Hint:
    %{
        ids.low = ids.a & ((1<<128) - 1)
        ids.high = ids.a >> 128
    %}
*/
pub fn uint384_split_128(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let a = get_integer_from_var_name("a", vm, ids_data, ap_tracking)?.into_owned();
    insert_value_from_var_name(
        "low",
        &a & &Felt252::from(u128::MAX),
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name("high", a >> 128_u32, vm, ids_data, ap_tracking)
}

/* Implements Hint:
%{
    sum_d0 = ids.a.d0 + ids.b.d0
    ids.carry_d0 = 1 if sum_d0 >= ids.SHIFT else 0
    sum_d1 = ids.a.d1 + ids.b.d1 + ids.carry_d0
    ids.carry_d1 = 1 if sum_d1 >= ids.SHIFT else 0
    sum_d2 = ids.a.d2 + ids.b.d2 + ids.carry_d1
    ids.carry_d2 = 1 if sum_d2 >= ids.SHIFT else 0
%}
 */
pub fn add_no_uint384_check(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let a = BigInt3::from_var_name("a", vm, ids_data, ap_tracking)?;
    let b = BigInt3::from_var_name("b", vm, ids_data, ap_tracking)?;
    // This hint is not from the cairo commonlib, and its lib can be found under different paths, so we cant rely on a full path name
    let (_, shift) = constants
        .iter()
        .find(|(k, _)| k.rsplit('.').next() == Some("SHIFT"))
        .ok_or(HintError::MissingConstant("SHIFT"))?;

    let sum_d0 = a.d0.as_ref() + b.d0.as_ref();
    let carry_d0 = Felt252::from((&sum_d0 >= shift) as usize);
    let sum_d1 = a.d1.as_ref() + b.d1.as_ref();
    let carry_d1 = Felt252::from((&sum_d1 >= shift) as usize);
    let sum_d2 = a.d2.as_ref() + b.d2.as_ref();
    let carry_d2 = Felt252::from((&sum_d2 >= shift) as usize);

    insert_value_from_var_name("carry_d0", carry_d0, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name("carry_d1", carry_d1, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name("carry_d2", carry_d2, vm, ids_data, ap_tracking)
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
        types::{
            exec_scope::ExecutionScopes,
            relocatable::{MaybeRelocatable, Relocatable},
        },
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, runners::builtin_runner::RangeCheckBuiltinRunner,
            vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use assert_matches::assert_matches;
    use felt::felt_str;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_unsigned_div_rem_ok() {
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Create hint_data
        let ids_data =
            non_continuous_ids_data![("a", -9), ("div", -6), ("quotient", -3), ("remainder", 0)];
        //Insert ids into memory
        vm.segments = segments![
            //a
            ((1, 1), 83434123481193248),
            ((1, 2), 82349321849739284),
            ((1, 3), 839243219401320423),
            //div
            ((1, 4), 9283430921839492319493),
            ((1, 5), 313248123482483248),
            ((1, 6), 3790328402913840)
        ];
        //Execute the hint
        assert_matches!(
            run_hint!(vm, ids_data, hint_code::UINT384_UNSIGNED_DIV_REM),
            Ok(())
        );
        //Check hint memory inserts
        check_memory![
            vm.segments.memory,
            // quotient
            ((1, 7), 221),
            ((1, 8), 0),
            ((1, 9), 0),
            // remainder
            //((1, 10), 340282366920936411825224315027446796751),
            //((1, 11), 340282366920938463394229121463989152931),
            ((1, 12), 1580642357361782)
        ];
        assert_eq!(
            vm.segments
                .memory
                .get_integer((1, 10).into())
                .unwrap()
                .as_ref(),
            &felt_str!("340282366920936411825224315027446796751")
        );
        assert_eq!(
            vm.segments
                .memory
                .get_integer((1, 11).into())
                .unwrap()
                .as_ref(),
            &felt_str!("340282366920938463394229121463989152931")
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_unsigned_div_rem_invalid_memory_insert() {
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Create hint_data
        let ids_data =
            non_continuous_ids_data![("a", -9), ("div", -6), ("quotient", -3), ("remainder", 0)];
        //Insert ids into memory
        vm.segments = segments![
            //a
            ((1, 1), 83434123481193248),
            ((1, 2), 82349321849739284),
            ((1, 3), 839243219401320423),
            //div
            ((1, 4), 9283430921839492319493),
            ((1, 5), 313248123482483248),
            ((1, 6), 3790328402913840),
            //quotient
            ((1, 7), 2)
        ];
        //Execute the hint
        assert_matches!(
            run_hint!(vm, ids_data, hint_code::UINT384_UNSIGNED_DIV_REM),
            Err(HintError::Memory(
                MemoryError::InconsistentMemory(
                    x,
                    y,
                    z,
                )
            )) if x == Relocatable::from((1, 7)) &&
                    y == MaybeRelocatable::from(Felt252::new(2)) &&
                    z == MaybeRelocatable::from(Felt252::new(221))
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_split_128_ok() {
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Create hint_data
        let ids_data = ids_data!["a", "low", "high"];
        //Insert ids into memory
        vm.segments = segments![((1, 0), 34895349583295832495320945304)];
        //Execute the hint
        assert_matches!(
            run_hint!(vm, ids_data, hint_code::UINT384_SPLIT_128),
            Ok(())
        );
        //Check hint memory inserts
        check_memory![
            vm.segments.memory,
            // low
            ((1, 1), 34895349583295832495320945304),
            // high
            ((1, 2), 0)
        ];
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_split_128_ok_big_number() {
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Create hint_data
        let ids_data = ids_data!["a", "low", "high"];
        //Insert ids into memory
        vm.segments.add();
        vm.segments.add();
        vm.segments
            .memory
            .insert(
                (1, 0).into(),
                Felt252::from(u128::MAX) * Felt252::from(20_u32),
            )
            .unwrap();
        //Execute the hint
        assert_matches!(
            run_hint!(vm, ids_data, hint_code::UINT384_SPLIT_128),
            Ok(())
        );
        //Check hint memory inserts
        check_memory![
            vm.segments.memory,
            // low
            //((1, 1), 340282366920938463463374607431768211454)
            // high
            ((1, 2), 19)
        ];
        assert_eq!(
            vm.segments
                .memory
                .get_integer((1, 1).into())
                .unwrap()
                .as_ref(),
            &felt_str!("340282366920938463463374607431768211436")
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_split_128_invalid_memory_insert() {
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Create hint_data
        let ids_data = ids_data!["a", "low", "high"];
        //Insert ids into memory
        vm.segments = segments![((1, 0), 34895349583295832495320945304), ((1, 1), 2)];
        //Execute the hint
        assert_matches!(
            run_hint!(vm, ids_data, hint_code::UINT384_SPLIT_128),
            Err(HintError::Memory(
                MemoryError::InconsistentMemory(
                    x,
                    y,
                    z,
                )
            )) if x == Relocatable::from((1, 1)) &&
                    y == MaybeRelocatable::from(Felt252::new(2)) &&
                    z == MaybeRelocatable::from(Felt252::new(34895349583295832495320945304_i128))
        );
    }
}

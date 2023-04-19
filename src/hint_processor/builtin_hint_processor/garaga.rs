use crate::stdlib::collections::HashMap;
use crate::stdlib::prelude::String;

use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

use super::hint_utils::{get_integer_from_var_name, insert_value_from_var_name};

/// Implements hint:
/// ```python
/// x = ids.x,
/// ids.bit_length = x.bit_length()
/// ```
pub fn get_felt_bitlenght(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let x = get_integer_from_var_name("x", vm, ids_data, ap_tracking)?;
    let bit_length = x.bits() as usize;
    insert_value_from_var_name("bit_length", bit_length, vm, ids_data, ap_tracking)
}

#[cfg(test)]
mod tests {
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::hint_processor_utils::felt_to_u32;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::vm_memory::memory::Memory;
    use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
    use crate::{hint_processor::builtin_hint_processor::hint_code, utils::test_utils::*};
    use assert_matches::assert_matches;
    use felt::Felt252;

    use super::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_7_bit_length_is_3() {
        let ids_data = non_continuous_ids_data![
            ("x", 0),          // located at `fp + 0`.
            ("bit_length", 1)  // located at `fp + 1`.
        ];

        let mut vm = vm!();
        vm.run_context.fp = 0;
        vm.segments = segments![
            ((1, 0), 7) // Inits `ids.x` to `7`.
                        // Don't initialize `fp + 1` for `ids.bit_length`!
        ];

        assert_matches!(
            run_hint!(vm, ids_data, hint_code::GET_FELT_BIT_LENGTH),
            Ok(())
        );

        let bit_length = felt_to_u32(&vm.get_integer((1, 1).into()).unwrap()).unwrap();
        assert_eq!(bit_length, 3);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_in_range() {
        for i in 0..252 {
            let x: Felt252 = Felt252::new(1) << i;

            let ids_data = non_continuous_ids_data![
                ("x", 0),          // located at `fp + 0`.
                ("bit_length", 1)  // located at `fp + 1`.
            ];

            let mut vm = vm!();
            vm.run_context.fp = 0;
            add_segments!(vm, 2); // Alloc space for `ids.x` and `ids.bit_length`
            vm.insert_value((1, 0).into(), x).unwrap();

            assert_matches!(
                run_hint!(vm, ids_data, hint_code::GET_FELT_BIT_LENGTH),
                Ok(())
            );

            let bit_length = felt_to_u32(&vm.get_integer((1, 1).into()).unwrap()).unwrap();
            assert_eq!(bit_length, i + 1);
        }
    }
}

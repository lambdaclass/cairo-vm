use crate::hint_processor::proxies::vm_proxy::VMProxy;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::{bigint, hint_processor::hint_processor_definition::HintReference};
use num_bigint::BigInt;
use num_integer::Integer;
use std::collections::HashMap;

use crate::hint_processor::builtin_hint_processor::hint_utils::{
    get_relocatable_from_var_name, insert_value_from_var_name,
};

/*
Implements hint:
%{ ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1 %}
*/
pub fn pow(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let prev_locs_addr =
        get_relocatable_from_var_name("prev_locs", vm_proxy, ids_data, ap_tracking)?;
    let prev_locs_exp = vm_proxy.get_integer(&(&prev_locs_addr + 4))?;
    let locs_bit = prev_locs_exp.mod_floor(vm_proxy.get_prime()) & bigint!(1);
    insert_value_from_var_name("locs", locs_bit, vm_proxy, ids_data, ap_tracking)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use crate::{bigint, vm::runners::builtin_runner::RangeCheckBuiltinRunner};
    use num_bigint::{BigInt, Sign};
    use std::any::Any;

    use super::*;

    #[test]
    fn run_pow_ok() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1";
        let mut vm = vm_with_range_check!();
        //Initialize ap
        vm.run_context.fp = 12;
        vm.memory = memory![((1, 11), 3)];
        let ids_data = non_continuous_ids_data![("prev_locs", -5), ("locs", 0)];
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check hint memory inserts
        check_memory![vm.memory, ((1, 12), 1)];
    }

    #[test]
    fn run_pow_incorrect_ids() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 2);
        //Initialize ap
        vm.run_context.ap = 11;
        //Create incorrect ids
        let ids_data = ids_data!["locs"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_pow_incorrect_references() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 2);
        //Initialize fp
        vm.run_context.fp = 11;
        //Create hint_data
        let ids_data = non_continuous_ids_data![("prev_locs", -5), ("locs", -12)];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 10))
            ))
        );
    }

    #[test]
    fn run_pow_prev_locs_exp_is_not_integer() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 11;
        //Create hint_data
        let ids_data = non_continuous_ids_data![("prev_locs", -5), ("locs", -12)];
        //Insert ids.prev_locs.exp into memory as a RelocatableValue
        vm.memory = memory![((1, 10), (1, 11))];
        add_segments!(vm, 1);
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 10))
            ))
        );
    }

    #[test]
    fn run_pow_invalid_memory_insert() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1";
        let mut vm = vm_with_range_check!();
        //Initialize ap
        vm.run_context.fp = 11;
        //Create hint_data
        let ids_data = non_continuous_ids_data![("prev_locs", -5), ("locs", 0)];
        //Insert ids into memory
        vm.memory = memory![((1, 10), 3), ((1, 11), 3)];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 11)),
                    MaybeRelocatable::from(bigint!(3)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }
}

use crate::bigint;
use crate::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;
use crate::hint_processor::proxies::vm_proxy::VMProxy;
use crate::{
    hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name,
    serde::deserialize_program::ApTracking,
};
use num_bigint::BigInt;
use std::any::Any;
use std::collections::HashMap;

use crate::{
    hint_processor::builtin_hint_processor::hint_utils::insert_value_into_ap,
    vm::errors::vm_errors::VirtualMachineError,
};

///Implements hint: memory[ap] = segments.add()
pub fn add_segment(vm_proxy: &mut VMProxy) -> Result<(), VirtualMachineError> {
    let new_segment_base = vm_proxy.memory.add_segment(vm_proxy.segments);
    insert_value_into_ap(&mut vm_proxy.memory, vm_proxy.run_context, new_segment_base)
}

//Implements hint: vm_enter_scope()
pub fn enter_scope(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    exec_scopes_proxy.enter_scope(HashMap::new());
    Ok(())
}

//  Implements hint:
//  %{ vm_exit_scope() %}
pub fn exit_scope(exec_scopes_proxy: &mut ExecutionScopesProxy) -> Result<(), VirtualMachineError> {
    exec_scopes_proxy
        .exit_scope()
        .map_err(VirtualMachineError::MainScopeError)
}

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.len}) %}
pub fn memcpy_enter_scope(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let len: Box<dyn Any> =
        Box::new(get_integer_from_var_name("len", vm_proxy, ids_data, ap_tracking)?.clone());
    exec_scopes_proxy.enter_scope(HashMap::from([(String::from("n"), len)]));
    Ok(())
}

// Implements hint:
// %{
//     n -= 1
//     ids.continue_copying = 1 if n > 0 else 0
// %}
pub fn memcpy_continue_copying(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    // get `n` variable from vm scope
    let n = exec_scopes_proxy.get_int_ref("n")?;
    // this variable will hold the value of `n - 1`
    let new_n = n - 1;
    // if it is positive, insert 1 in the address of `continue_copying`
    // else, insert 0
    if new_n.is_positive() {
        insert_value_from_var_name(
            "continue_copying",
            bigint!(1),
            vm_proxy,
            ids_data,
            ap_tracking,
        )?;
    } else {
        insert_value_from_var_name(
            "continue_copying",
            bigint!(0),
            vm_proxy,
            ids_data,
            ap_tracking,
        )?;
    }
    exec_scopes_proxy.insert_value("n", new_n);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::BigInt;
    use num_bigint::Sign;

    #[test]
    fn get_integer_from_var_name_valid() {
        let mut vm = vm!();
        // initialize memory segments
        vm.segments.add(&mut vm.memory);

        // initialize fp
        vm.run_context.fp = 1;

        let var_name: &str = "variable";

        //Create ids_data
        let ids_data = ids_data![var_name];

        //Insert ids.prev_locs.exp into memory
        vm.memory = memory![((1, 0), 10)];

        let vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            get_integer_from_var_name(var_name, &vm_proxy, &ids_data, &ApTracking::default()),
            Ok(&felt!(10))
        );
    }

    #[test]
    fn get_integer_from_var_name_invalid_expected_integer() {
        let mut vm = vm!();

        // initialize fp
        vm.run_context.fp = 1;

        let var_name: &str = "variable";

        //Create ids_data
        let ids_data = ids_data![var_name];

        //Insert ids.variable into memory as a RelocatableValue
        vm.memory = memory![((1, 0), (1, 1))];

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            get_integer_from_var_name(var_name, vm_proxy, &ids_data, &ApTracking::default()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 0))
            ))
        );
    }
}

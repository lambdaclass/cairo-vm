use std::collections::HashMap;

use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::{
            enter_scope_with_n_from_var_name, insert_value_into_ap,
        },
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    types::exec_scope::ExecutionScopes,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

//Implements hint: memory[ap] = segments.add()
pub fn add_segment(vm: &mut VirtualMachine) -> Result<(), HintError> {
    let new_segment_base = vm.add_memory_segment();
    insert_value_into_ap(vm, new_segment_base)
}

//Implements hint: vm_enter_scope()
pub fn enter_scope(exec_scopes: &mut ExecutionScopes) -> Result<(), HintError> {
    exec_scopes.enter_scope(HashMap::new());
    Ok(())
}

//  Implements hint:
//  %{ vm_exit_scope() %}
pub fn exit_scope(exec_scopes: &mut ExecutionScopes) -> Result<(), HintError> {
    exec_scopes.exit_scope().map_err(HintError::FromScopeError)
}

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.len}) %}
pub fn memcpy_enter_scope(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    enter_scope_with_n_from_var_name("len", vm, exec_scopes, ids_data, ap_tracking)
}

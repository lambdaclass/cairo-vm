use crate::hint_processor::hint_processor_definition::HintReference;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopes;
use crate::vm::errors::hint_errors::HintError;
use crate::vm::vm_core::VirtualMachine;
use crate::Felt252;
use std::collections::HashMap;

/// Prevent the execution of the next instruction
///
/// This hint doesn't belong to the Cairo common library
/// It's only added for testing purposes
pub fn skip_next_instruction(
    vm: &mut VirtualMachine,
    _exec_scopes: &mut ExecutionScopes,
    _ids_data: &HashMap<String, HintReference>,
    _ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    vm.skip_next_instruction_execution();
    Ok(())
}

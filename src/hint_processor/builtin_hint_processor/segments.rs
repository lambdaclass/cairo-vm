use crate::hint_processor::builtin_hint_processor::hint_utils::get_relocatable_from_var_name;

use crate::hint_processor::hint_processor_definition::HintReference;

use crate::serde::deserialize_program::ApTracking;

use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;

use std::collections::HashMap;

/*
Implements hint:
%{ memory.add_relocation_rule(src_ptr=ids.src_ptr, dest_ptr=ids.dest_ptr) %}
*/
pub fn relocate_segment(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let src_ptr = get_relocatable_from_var_name("src_ptr", vm, ids_data, ap_tracking)?;
    let dest_ptr = get_relocatable_from_var_name("dest_ptr", vm, ids_data, ap_tracking)?;

    vm.memory.add_relocation_rule(src_ptr, dest_ptr)?;
    Ok(())
}

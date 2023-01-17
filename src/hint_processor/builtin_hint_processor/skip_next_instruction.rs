#[cfg(feature = "skip_next_instruction_hint")]
use crate::vm::errors::hint_errors::HintError;
#[cfg(feature = "skip_next_instruction_hint")]
use crate::vm::vm_core::VirtualMachine;

/*
This hint doesn't belong to the Cairo common library
It's only added for testing proposes
*/

#[cfg(feature = "skip_next_instruction_hint")]
pub fn skip_next_instruction(vm: &mut VirtualMachine) -> Result<(), HintError> {
    vm.skip_next_instruction_execution();
    Ok(())
}

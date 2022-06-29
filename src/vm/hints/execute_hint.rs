use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::add_segment;
use crate::vm::vm_core::VirtualMachine;

pub fn execute_hint(
    vm: &mut VirtualMachine,
    hint_code: &Vec<u8>,
) -> Result<(), VirtualMachineError> {
    match std::str::from_utf8(hint_code).unwrap() {
        "memory[ap] = segments.add()" => add_segment(vm),
        _ => Ok(()),
    }
}

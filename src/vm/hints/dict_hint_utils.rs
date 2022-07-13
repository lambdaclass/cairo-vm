use crate::vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine};

use super::dict_manager::DictManager;

///Implements hint: if '__dict_manager' not in globals():
///            from starkware.cairo.common.dict import DictManager
///            __dict_manager = DictManager()
///
///        memory[ap] = __dict_manager.new_dict(segments, initial_dict)
///        del initial_dict
///
/// For now, the functionality to create a dictionary from a previously defined initial_dict (using a hint)
/// is not available, an empty dict is created always
pub fn dict_new(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    if vm.dict_manager.is_none() {
        vm.dict_manager = Some(DictManager::new());
    }
    //This unwrap will never fail as dict_manager is checked for None value beforehand
    let base = vm
        .dict_manager
        .as_mut()
        .unwrap()
        .new_dict(&mut vm.segments, &mut vm.memory)?;
    vm.memory
        .insert(&vm.run_context.ap, &base)
        .map_err(VirtualMachineError::MemoryError)
}

use crate::vm::vm_core::VirtualMachine;

pub fn add_segment(vm: &VirtualMachine) {
    vm.memory.insert(vm.segments.add(None));
}

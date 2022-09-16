use num_bigint::BigInt;

use crate::vm::{
    context::run_context::RunContext,
    runners::builtin_runner::BuiltinRunner,
    vm_core::VirtualMachine,
    vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
};

use super::memory_proxy::{get_memory_proxy, MemoryProxy};

///Structure representing a limited access to the VM's internal values
pub struct VMProxy<'a> {
    pub memory: MemoryProxy<'a>,
    pub segments: &'a mut MemorySegmentManager,
    pub run_context: &'a mut RunContext,
    pub builtin_runners: &'a Vec<(String, Box<dyn BuiltinRunner>)>,
    pub prime: &'a BigInt,
}

///Creates a VMProxy from a VM instance
pub fn get_vm_proxy(vm: &mut VirtualMachine) -> VMProxy {
    let mut memory = Memory::new();
    let mut segments = MemorySegmentManager::new();
    VMProxy {
        memory: get_memory_proxy(&mut memory),
        segments: &mut segments,
        run_context: &mut vm.run_context,
        builtin_runners: &vm.builtin_runners,
        prime: &vm.prime,
    }
}

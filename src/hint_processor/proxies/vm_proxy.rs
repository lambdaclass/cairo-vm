use std::{cell::RefCell, rc::Rc};

use num_bigint::BigInt;

use crate::vm::vm_memory::memory::Memory;
use crate::vm::{
    context::run_context::RunContext, runners::builtin_runner::BuiltinRunner,
    vm_core::VirtualMachine, vm_memory::memory_segments::MemorySegmentManager,
};

use super::memory_proxy::{get_memory_proxy, MemoryProxy};

///Structure representing a limited access to the VM's internal values
pub struct VMProxy<'a> {
    pub memory: Rc<RefCell<MemoryProxy>>,
    pub segments: Rc<RefCell<MemorySegmentManager>>,
    pub run_context: &'a mut RunContext,
    pub builtin_runners: &'a Vec<(String, Box<dyn BuiltinRunner>)>,
    pub prime: &'a BigInt,
}

///Creates a VMProxy from a VM instance
pub fn get_vm_proxy(vm: &mut VirtualMachine) -> VMProxy {
    VMProxy {
        //TODO: Replace with Rc::clone(vm.memory)
        memory: Rc::new(RefCell::new(get_memory_proxy(&Rc::new(RefCell::new(
            Memory::new(),
        ))))),
        //TODO: Replace with Rc::clone(vm.segments)
        segments: Rc::new(RefCell::new(MemorySegmentManager::new())),
        run_context: &mut vm.run_context,
        builtin_runners: &vm.builtin_runners,
        prime: &vm.prime,
    }
}

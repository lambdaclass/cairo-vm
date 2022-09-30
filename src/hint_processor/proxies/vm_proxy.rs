use std::any::Any;

use num_bigint::BigInt;

use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        context::run_context::RunContext,
        errors::{memory_errors::MemoryError, vm_errors::VirtualMachineError},
        runners::builtin_runner::BuiltinRunner,
        vm_core::VirtualMachine,
        vm_memory::memory_segments::MemorySegmentManager,
    },
};

use super::memory_proxy::{get_memory_proxy, MemoryProxy};

///Structure representing a limited access to the VM's internal values
pub struct VMProxy<'a> {
    pub memory: MemoryProxy<'a>,
    pub segments: &'a mut MemorySegmentManager,
    run_context: &'a mut RunContext,
    pub builtin_runners: &'a Vec<(String, Box<dyn BuiltinRunner>)>,
    pub prime: &'a BigInt,
}

///Creates a VMProxy from a VM instance
pub fn get_vm_proxy(vm: &mut VirtualMachine) -> VMProxy {
    VMProxy {
        memory: get_memory_proxy(&mut vm.memory),
        segments: &mut vm.segments,
        run_context: &mut vm.run_context,
        builtin_runners: &vm.builtin_runners,
        prime: &vm.prime,
    }
}

impl VMProxy<'_> {
    ///Adds a new segment and to the VMProxy.memory returns its starting location as a RelocatableValue.
    pub fn add_memory_segment(&mut self) -> Relocatable {
        self.memory.add_segment(self.segments)
    }

    pub fn get_ap(&self) -> Relocatable {
        self.run_context.get_ap()
    }

    pub fn get_fp(&self) -> Relocatable {
        self.run_context.get_fp()
    }

    pub fn get_prime(&self) -> &BigInt {
        self.prime
    }

    ///Gets the integer value corresponding to the Relocatable address
    pub fn get_integer(&self, key: &Relocatable) -> Result<&BigInt, VirtualMachineError> {
        self.memory.get_integer(key)
    }

    ///Gets the relocatable value corresponding to the Relocatable address
    pub fn get_relocatable(&self, key: &Relocatable) -> Result<&Relocatable, VirtualMachineError> {
        self.memory.get_relocatable(key)
    }

    ///Gets a MaybeRelocatable value from memory indicated by a generic address
    pub fn get_maybe<'a, K: 'a>(&self, key: &'a K) -> Result<Option<&MaybeRelocatable>, MemoryError>
    where
        Relocatable: TryFrom<&'a K>,
    {
        self.memory.get(key)
    }

    ///Inserts a value into a memory address given by a Relocatable value
    pub fn insert_value<T: Into<MaybeRelocatable>>(
        &mut self,
        key: &Relocatable,
        val: T,
    ) -> Result<(), VirtualMachineError> {
        self.memory.insert_value(key, val)
    }

    ///Writes data into the memory at address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        ptr: &MaybeRelocatable,
        data: Vec<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        self.memory.load_data(self.segments, ptr, data)
    }

    //// Writes args into the memory at address ptr and returns the first address after the data.
    /// Perfroms modulo on each element
    pub fn write_arg(
        &mut self,
        ptr: &Relocatable,
        arg: &dyn Any,
    ) -> Result<MaybeRelocatable, MemoryError> {
        self.memory
            .write_arg(self.segments, ptr, arg, Some(self.prime))
    }

    ///Gets n elements from memory starting from addr (n being size)
    pub fn get_range(
        &self,
        addr: &MaybeRelocatable,
        size: usize,
    ) -> Result<Vec<Option<&MaybeRelocatable>>, MemoryError> {
        self.memory.get_range(addr, size)
    }

    ///Gets n integer values from memory starting from addr (n being size),
    pub fn get_integer_range(
        &self,
        addr: &Relocatable,
        size: usize,
    ) -> Result<Vec<&BigInt>, VirtualMachineError> {
        self.memory.get_integer_range(addr, size)
    }
}

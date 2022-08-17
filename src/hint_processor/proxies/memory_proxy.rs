use std::any::Any;

use num_bigint::BigInt;

use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::{memory_errors::MemoryError, vm_errors::VirtualMachineError},
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
};

pub struct MemoryProxy<'a> {
    memory: &'a mut Memory,
}

pub fn get_memory_proxy(memory: &mut Memory) -> MemoryProxy {
    MemoryProxy { memory }
}

impl MemoryProxy<'_> {
    pub fn insert_value<T: Into<MaybeRelocatable>>(
        &mut self,
        key: &Relocatable,
        val: T,
    ) -> Result<(), VirtualMachineError> {
        self.memory.insert_value(key, val)
    }

    pub fn get_integer(&self, key: &Relocatable) -> Result<&BigInt, VirtualMachineError> {
        self.memory.get_integer(key)
    }

    pub fn get_relocatable(&self, key: &Relocatable) -> Result<&Relocatable, VirtualMachineError> {
        self.memory.get_relocatable(key)
    }

    pub fn get_range(
        &self,
        addr: &MaybeRelocatable,
        size: usize,
    ) -> Result<Vec<Option<&MaybeRelocatable>>, MemoryError> {
        self.memory.get_range(addr, size)
    }

    pub fn get_integer_range(
        &self,
        addr: &Relocatable,
        size: usize,
    ) -> Result<Vec<&BigInt>, VirtualMachineError> {
        self.memory.get_integer_range(addr, size)
    }

    pub fn get<'a, K: 'a>(&self, key: &'a K) -> Result<Option<&MaybeRelocatable>, MemoryError>
    where
        Relocatable: TryFrom<&'a K>,
    {
        self.memory.get(key)
    }

    pub fn write_arg(
        &mut self,
        segments: &mut MemorySegmentManager,
        ptr: &Relocatable,
        arg: &dyn Any,
        prime: Option<&BigInt>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        segments.write_arg(self.memory, ptr, arg, prime)
    }

    pub fn add_segment(&mut self, segments: &mut MemorySegmentManager) -> Relocatable {
        segments.add(self.memory, None)
    }

    ///Writes data into the memory at address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        segments: &mut MemorySegmentManager,
        ptr: &MaybeRelocatable,
        data: Vec<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        segments.load_data(self.memory, ptr, data)
    }
}

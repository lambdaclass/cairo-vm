use std::{any::Any, cell::RefCell, rc::Rc};

use num_bigint::BigInt;

use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::{memory_errors::MemoryError, vm_errors::VirtualMachineError},
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
};

///Structure representing a limited access to the VM's Memory
pub struct MemoryProxy {
    memory: Rc<RefCell<Memory>>,
}

///Returns a MemoryProxy from a Memory
pub fn get_memory_proxy(memory: &Rc<RefCell<Memory>>) -> MemoryProxy {
    MemoryProxy {
        memory: Rc::clone(memory),
    }
}

impl MemoryProxy {
    ///Inserts a value into a memory address given by a Relocatable value
    pub fn insert_value<T: Into<MaybeRelocatable>>(
        &mut self,
        key: &Relocatable,
        val: T,
    ) -> Result<(), VirtualMachineError> {
        self.memory.borrow_mut().insert_value(key, val)
    }

    ///Gets the integer value corresponding to the Relocatable address
    pub fn get_integer(&self, key: &Relocatable) -> Result<BigInt, VirtualMachineError> {
        self.memory.borrow().get_integer(key).cloned()
    }

    ///Gets the relocatable value corresponding to the Relocatable address
    pub fn get_relocatable(&self, key: &Relocatable) -> Result<Relocatable, VirtualMachineError> {
        self.memory.borrow().get_relocatable(key).cloned()
    }

    ///Gets n elements from memory starting from addr (n being size)
    pub fn get_range(
        &self,
        addr: &MaybeRelocatable,
        size: usize,
    ) -> Result<Vec<Option<MaybeRelocatable>>, MemoryError> {
        self.memory.borrow().get_range(addr, size)
    }

    ///Gets n integer values from memory starting from addr (n being size),
    pub fn get_integer_range(
        &self,
        addr: &Relocatable,
        size: usize,
    ) -> Result<Vec<BigInt>, VirtualMachineError> {
        self.memory.borrow_mut().get_integer_range(addr, size)
    }

    ///Gets a MaybeRelocatable value from memory indicated by a generic address
    pub fn get<'a, K: 'a>(&self, key: &'a K) -> Result<Option<MaybeRelocatable>, MemoryError>
    where
        Relocatable: TryFrom<&'a K>,
    {
        Ok(self.memory.borrow_mut().get(key)?.cloned())
    }

    //// Writes args into the memory at address ptr and returns the first address after the data.
    /// Perfroms modulo on each element
    pub fn write_arg(
        &mut self,
        segments: &mut MemorySegmentManager,
        ptr: &Relocatable,
        arg: &dyn Any,
        prime: Option<&BigInt>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        segments.write_arg(&mut self.memory.borrow_mut(), ptr, arg, prime)
    }

    /// Adds a new memory segment and returns it base
    pub fn add_segment(&mut self, segments: &mut MemorySegmentManager) -> Relocatable {
        segments.add(&mut self.memory.borrow_mut())
    }

    ///Writes data into the memory at address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        segments: &mut MemorySegmentManager,
        ptr: &MaybeRelocatable,
        data: Vec<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        segments.load_data(&mut self.memory.borrow_mut(), ptr, data)
    }
}

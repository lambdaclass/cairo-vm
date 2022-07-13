use std::collections::HashMap;

use num_bigint::BigInt;

use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::vm_errors::VirtualMachineError,
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
};

#[derive(PartialEq, Debug)]
///Manages dictionaries in a Cairo program.
///Uses the segment index to associate the corresponding python dict with the Cairo dict.
pub struct DictManager {
    pub trackers: HashMap<usize, DictTracker>,
}

#[derive(PartialEq, Debug)]
///Tracks the python dict associated with a Cairo dict.
pub struct DictTracker {
    //Dictionary.
    pub data: HashMap<BigInt, BigInt>,
    //Pointer to the first unused position in the dict segment.
    pub current_ptr: Relocatable,
}

impl DictManager {
    pub fn new() -> Self {
        DictManager {
            trackers: HashMap::<usize, DictTracker>::new(),
        }
    }
    //Creates a new Cairo dictionary. The values of initial_dict can be integers, tuples or
    //lists. See MemorySegments.gen_arg().
    //For now, no initial dict will be processed (Assumes initial_dict = None)
    pub fn new_dict(
        &mut self,
        segments: &mut MemorySegmentManager,
        memory: &mut Memory,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base = segments.add(memory, None);
        if self.trackers.contains_key(&base.segment_index) {
            return Err(VirtualMachineError::CantCreateDictionaryOnTakenSegment(
                base.segment_index,
            ));
        }
        self.trackers
            .insert(base.segment_index, DictTracker::new_empty(&base));
        Ok(MaybeRelocatable::RelocatableValue(base))
    }
}

impl DictTracker {
    pub fn new_empty(base: &Relocatable) -> Self {
        DictTracker {
            data: HashMap::new(),
            current_ptr: base.clone(),
        }
    }
}

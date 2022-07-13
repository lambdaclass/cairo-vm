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

impl Default for DictManager {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod tests {
    use crate::relocatable;

    use super::*;

    #[test]
    fn create_dict_manager() {
        let dict_manager = DictManager::new();
        assert_eq!(dict_manager.trackers, HashMap::new());
    }

    #[test]
    fn create_dict_tracker_empty() {
        let dict_tracker = DictTracker::new_empty(&relocatable!(1, 0));
        assert_eq!(dict_tracker.data, HashMap::new());
        assert_eq!(dict_tracker.current_ptr, relocatable!(1, 0));
    }

    #[test]
    fn dict_manager_new_dict_empty() {
        let mut dict_manager = DictManager::new();
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        let base = dict_manager.new_dict(&mut segments, &mut memory);
        assert_eq!(base, Ok(MaybeRelocatable::from((0, 0))));
        assert!(dict_manager.trackers.contains_key(&0));
        assert_eq!(
            dict_manager.trackers.get(&0),
            Some(&DictTracker::new_empty(&relocatable!(0, 0)))
        );
        assert_eq!(segments.num_segments, 1);
    }

    #[test]
    fn dict_manager_new_dict_empty_same_segment() {
        let mut dict_manager = DictManager::new();
        dict_manager
            .trackers
            .insert(0, DictTracker::new_empty(&relocatable!(0, 0)));
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        assert_eq!(
            dict_manager.new_dict(&mut segments, &mut memory),
            Err(VirtualMachineError::CantCreateDictionaryOnTakenSegment(0))
        );
    }
}

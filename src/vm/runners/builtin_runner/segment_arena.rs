use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_memory::memory::Memory;
use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_memory::memory_segments::MemorySegmentManager,
};

use super::SEGMENT_ARENA_BUILTIN_NAME;

const ARENA_BUILTIN_SIZE: u32 = 3;
// The size of the builtin segment at the time of its creation.
const INITIAL_SEGMENT_SIZE: usize = ARENA_BUILTIN_SIZE as usize;

#[derive(Debug, Clone)]
pub struct SegmentArenaBuiltinRunner {
    base: Relocatable,
    included: bool,
    pub(crate) cells_per_instance: u32,
    pub(crate) n_input_cells_per_instance: u32,
    pub(crate) stop_ptr: Option<usize>,
}

impl SegmentArenaBuiltinRunner {
    pub(crate) fn new(included: bool) -> Self {
        SegmentArenaBuiltinRunner {
            base: Relocatable::from((0, 0)),
            included,
            cells_per_instance: ARENA_BUILTIN_SIZE,
            n_input_cells_per_instance: ARENA_BUILTIN_SIZE,
            stop_ptr: None,
        }
    }

    pub fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        let info = &[
            MaybeRelocatable::from(segments.add()),
            MaybeRelocatable::from(0),
            MaybeRelocatable::from(0),
        ];
        let segment_start = gen_arg(segments, info);
        // 0 + 3 can't fail
        self.base = (segment_start + INITIAL_SEGMENT_SIZE).unwrap();
    }

    pub fn get_used_cells(&self, segments: &MemorySegmentManager) -> Result<usize, MemoryError> {
        let used = segments
            .get_segment_used_size(self.base.segment_index as usize)
            .ok_or(MemoryError::MissingSegmentUsedSizes)?;
        if used < INITIAL_SEGMENT_SIZE {
            return Err(MemoryError::InvalidUsedSizeSegmentArena);
        }
        Ok(used - INITIAL_SEGMENT_SIZE)
    }

    pub fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            vec![MaybeRelocatable::from(self.base)]
        } else {
            vec![]
        }
    }

    pub fn final_stack(
        &mut self,
        segments: &MemorySegmentManager,
        pointer: Relocatable,
    ) -> Result<Relocatable, RunnerError> {
        if self.included {
            let stop_pointer_addr = (pointer - 1)
                .map_err(|_| RunnerError::NoStopPointer(SEGMENT_ARENA_BUILTIN_NAME))?;
            let stop_pointer = segments
                .memory
                .get_relocatable(stop_pointer_addr)
                .map_err(|_| RunnerError::NoStopPointer(SEGMENT_ARENA_BUILTIN_NAME))?;
            if self.base.segment_index != stop_pointer.segment_index {
                return Err(RunnerError::InvalidStopPointerIndex(
                    SEGMENT_ARENA_BUILTIN_NAME,
                    stop_pointer,
                    self.base.segment_index as usize,
                ));
            }
            let used = self.get_used_cells(segments).map_err(RunnerError::Memory)?;
            if stop_pointer != (self.base + used)? {
                return Err(RunnerError::InvalidStopPointer(
                    SEGMENT_ARENA_BUILTIN_NAME,
                    (self.base + used)?,
                    stop_pointer,
                ));
            }
            self.stop_ptr = Some(stop_pointer.offset);
            Ok(stop_pointer_addr)
        } else {
            self.stop_ptr = Some(self.base.offset);
            Ok(pointer)
        }
    }

    pub fn get_used_instances(
        &self,
        segments: &MemorySegmentManager,
    ) -> Result<usize, MemoryError> {
        self.get_used_cells(segments)
    }

    pub fn get_memory_segment_addresses(&self) -> (usize, Option<usize>) {
        (self.base.segment_index as usize, self.stop_ptr)
    }

    pub fn add_validation_rule(&self, _memory: &mut Memory) {}

    pub fn deduce_memory_cell(
        &self,
        _address: Relocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    pub fn base(&self) -> usize {
        self.base.segment_index as usize
    }
}

// Specific non-failling version of gen_arg used specifically for SegmentArenaBuiltinRunner
fn gen_arg(segments: &mut MemorySegmentManager, data: &[MaybeRelocatable; 3]) -> Relocatable {
    let base = segments.add();
    for (num, value) in data.iter().enumerate() {
        // 0 + 3 can't fail, inserting into newly created segment can't fail
        segments
            .memory
            .insert(&(base + num).unwrap(), value)
            .unwrap();
    }
    base
}

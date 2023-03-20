use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::with_std::any::Any;
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
    pub(crate) stop_ptr: Option<Relocatable>,
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

    pub fn initialize_segments(
        &mut self,
        segments: &mut MemorySegmentManager,
    ) -> Result<(), MemoryError> {
        let segment_start = segments.gen_arg(&[
            MaybeRelocatable::from(segments.add()),
            MaybeRelocatable::from(0),
            MaybeRelocatable::from(0),
        ] as &dyn Any)?;
        self.base = (segment_start
            .get_relocatable()
            .ok_or(MemoryError::AddressNotRelocatable)?
            + INITIAL_SEGMENT_SIZE as usize)?;
        Ok(())
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
                    Relocatable::from((self.base + used)?),
                    Relocatable::from(stop_pointer),
                ));
            }
            self.stop_ptr = Some(stop_pointer);
            Ok(stop_pointer_addr)
        } else {
            self.stop_ptr = Some(self.base);
            Ok(pointer)
        }
    }
}

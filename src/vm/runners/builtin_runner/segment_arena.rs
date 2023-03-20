use crate::vm::errors::memory_errors::MemoryError;
use crate::with_std::any::Any;
use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_memory::memory_segments::MemorySegmentManager,
};

const ARENA_BUILTIN_SIZE: u32 = 3;
// The size of the builtin segment at the time of its creation.
const INITIAL_SEGMENT_SIZE: u32 = ARENA_BUILTIN_SIZE;

#[derive(Debug)]
pub struct SegmentArenaBuiltinRunner {
    base: Relocatable,
    included: bool,
    ratio: Option<u32>,
    cells_per_instance: u32,
    n_input_cells_per_instance: u32,
}

impl SegmentArenaBuiltinRunner {
    pub(crate) fn new(included: bool) -> Self {
        SegmentArenaBuiltinRunner {
            base: Relocatable::from((0, 0)),
            included,
            ratio: None,
            cells_per_instance: ARENA_BUILTIN_SIZE,
            n_input_cells_per_instance: ARENA_BUILTIN_SIZE,
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
}

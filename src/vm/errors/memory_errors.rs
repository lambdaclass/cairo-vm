use std::fmt;

use crate::types::relocatable::MaybeRelocatable;

#[derive(Debug, PartialEq)]
pub enum MemoryError {
    UnallocatedSegment(usize, usize),
    AddressNotRelocatable,
    NumOutOfBounds,
    FoundNonInt,
    InconsistentMemory(MaybeRelocatable, MaybeRelocatable, MaybeRelocatable),
    EffectiveSizesNotCalled,
    Relocation,
    WriteArg,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryError::UnallocatedSegment(len, accessed) => write!(
                f,
                "Can't insert into segment #{}; memory only has {} segment",
                accessed, len
            ),
            MemoryError::AddressNotRelocatable => write!(f, "Memory addresses must be relocatable"),
            MemoryError::NumOutOfBounds => write!(
                f,
                "Range-check validation failed, number is out of valid range"
            ),
            MemoryError::FoundNonInt => write!(
                f,
                "Range-check validation failed, encountered non-int value"
            ),
            MemoryError::InconsistentMemory(addr, val_a, val_b) => write!(
                f,
                "Inconsistent memory assignment at address {:?}. {:?} != {:?}",
                addr, val_a, val_b
            ),

            MemoryError::EffectiveSizesNotCalled => write!(
                f,
                "compute_effective_sizes should be called before relocate_segments"
            ),
            MemoryError::Relocation => write!(f, "Inconsistent Relocation"),
            MemoryError::WriteArg => write!(f, "Could not cast arguments"),
        }
    }
}

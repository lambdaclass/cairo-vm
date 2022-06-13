use std::fmt;

#[derive(Debug, PartialEq)]
pub enum MemoryError {
    UnallocatedSegment(usize, usize),
    AddressNotRelocatable,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryError::UnallocatedSegment(len, accessed) => write!(
                f,
                "Invalid segment #{}; memory only has {} segments",
                accessed, len
            ),
            MemoryError::AddressNotRelocatable => write!(f, "Memory addresses must be relocatable"),
        }
    }
}

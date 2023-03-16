#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use thiserror_no_std::Error;

use crate::vm::errors::memory_errors::MemoryError;

#[derive(Debug, PartialEq, Error)]
pub enum TraceError {
    #[error("Trace is not enabled for this run")]
    TraceNotEnabled,
    #[error("Trace is already relocated")]
    AlreadyRelocated,
    #[error("Trace register must be relocatable")]
    RegNotRelocatable,
    #[error("No relocation found for program segment")]
    NoRelocationFound,
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
}

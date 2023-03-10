use crate::vm::errors::memory_errors::MemoryError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum TraceError {
    #[error("Trace is not enabled for this run")]
    TraceNotEnabled,
    #[error("Trace is already relocated")]
    AlreadyRelocated,
    #[error("Trace register must be relocatable")]
    RegNotRelocatable,
    #[error("No relocation found for this segment")]
    NoRelocationFound,
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
}

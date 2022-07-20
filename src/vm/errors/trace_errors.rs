use crate::vm::errors::memory_errors::MemoryError;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum TraceError {
    TraceNotEnabled,
    AlreadyRelocated,
    RegNotRelocatable,
    NoRelocationFound,
    MemoryError(MemoryError),
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TraceError::TraceNotEnabled => write!(f, "Trace is not enabled for this run"),
            TraceError::AlreadyRelocated => write!(f, "Trace is already relocated"),
            TraceError::RegNotRelocatable => write!(f, "Trace register must be relocatable"),
            TraceError::NoRelocationFound => write!(f, "No relocation found for this segment"),
            TraceError::MemoryError(memory_error) => memory_error.fmt(f),
        }
    }
}

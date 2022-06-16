use crate::types::relocatable::MaybeRelocatable;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum RunnerError {
    NoExecBase,
    NoExecBaseForEntrypoint,
    NoProgBase,
    MissingMain,
    UninitializedBase,
    NumOutOfBounds,
    FoundNonInt,
    NonRelocatableAddress,
    FailedStringConversion,
    ExpectedInteger(MaybeRelocatable),
    MemoryGet(MaybeRelocatable),
}

impl fmt::Display for RunnerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RunnerError::NoExecBase => {
                write!(f, "Can't initialize state without an execution base")
            }
            RunnerError::NoProgBase => write!(f, "Can't initialize state without a program base"),
            RunnerError::NoExecBaseForEntrypoint => write!(
                f,
                "Can't initialize the function entrypoint without an execution base"
            ),
            RunnerError::MissingMain => write!(f, "Missing main()"),
            RunnerError::UninitializedBase => write!(f, "Uninitialized self.base"),
            RunnerError::NumOutOfBounds => write!(
                f,
                "Range-check validation failed, number is out of valid range"
            ),
            RunnerError::FoundNonInt => write!(
                f,
                "Range-check validation failed, encountered non-int value"
            ),
            RunnerError::NonRelocatableAddress => write!(f, "Memory addresses must be relocatable"),
            RunnerError::FailedStringConversion => {
                write!(f, "Failed to convert string to FieldElement")
            }

            RunnerError::ExpectedInteger(addr) => {
                write!(f, "Expected integer at address {:?}", addr)
            }

            RunnerError::MemoryGet(addr) => {
                write!(f, "Failed to retrieve value from address {:?}", addr)
            }
        }
    }
}

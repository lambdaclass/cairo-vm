use crate::types::relocatable::MaybeRelocatable;
use num_bigint::BigInt;

use super::memory_errors::MemoryError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum RunnerError {
    #[error("Can't initialize state without an execution base")]
    NoExecBase,
    #[error("Can't without a program base")]
    NoExecBaseForEntrypoint,
    #[error("Can't initialize the function entrypoint without an execution base")]
    NoProgBase,
    #[error("Missing main()")]
    MissingMain,
    #[error("Uninitialized self.base")]
    UninitializedBase,
    #[error("Failed to write program output")]
    WriteFail,
    #[error("Found None PC during VM initialization")]
    NoPC,
    #[error("Found None AP during VM initialization")]
    NoAP,
    #[error("Found None FP during VM initialization")]
    NoFP,
    #[error("Memory validation failed during VM initialization: {0}")]
    MemoryValidationError(MemoryError),
    #[error("Memory loading failed during state initialization: {0}")]
    MemoryInitializationError(MemoryError),
    #[error("Memory addresses must be relocatable")]
    NonRelocatableAddress,
    #[error("Failed to convert string to FieldElement")]
    FailedStringConversion,
    #[error("Expected integer at address {0:?}")]
    ExpectedInteger(MaybeRelocatable),
    #[error("Failed to retrieve value from address {0:?}")]
    MemoryGet(MaybeRelocatable),
    #[error("Failed to fetch memory address.")]
    FailedMemoryGet(MemoryError),
    #[error("EcOpBuiltin: m should be at most {0}")]
    EcOpBuiltinScalarLimit(BigInt),
}

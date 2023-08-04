use cairo_vm::vm::errors::{memory_errors::MemoryError, vm_errors::VirtualMachineError};
#[cfg(feature = "std")]
use thiserror_no_std::Error;

#[derive(Debug, Error)]
pub enum TraceDataError {
    #[error("Instruction is None when encoding")]
    InstructionIsNone,
    #[error(transparent)]
    InstructionDecodeError(#[from] VirtualMachineError),
    #[error(transparent)]
    FailedToGetRelocationTable(#[from] MemoryError),
}

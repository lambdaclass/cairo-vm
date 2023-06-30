use cairo_vm::vm::errors::{
    memory_errors::MemoryError, trace_errors::TraceError, vm_errors::VirtualMachineError,
};
#[cfg(feature = "std")]
use thiserror_no_std::Error;

#[derive(Debug, Error)]
pub enum TraceDataError {
    #[error("Instruction is None at pc {0} when encoding")]
    InstructionIsNone(String),
    #[error(transparent)]
    InstructionDecodeError(#[from] VirtualMachineError),
    #[error(transparent)]
    FailedToGetRelocationTable(#[from] MemoryError),
    #[error(transparent)]
    FailedToRelocateTrace(#[from] TraceError),
    #[error("Failed to read file {0}")]
    FailedToReadFile(String),
    #[error("Input file is None {0}")]
    InputFileIsNone(String),
    #[error("Instruction encoding must be convertible to a u64")]
    FailedToConvertInstructionEncoding,
    #[error("Offset must be convertible to a usize")]
    FailedToConvertOffset,
    #[error("Imm address {0} must be convertible to a usize")]
    FailedToImmAddress(String),
}

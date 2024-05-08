use thiserror_no_std::Error;

use super::cairo_pie_errors::CairoPieValidationError;
use super::memory_errors::MemoryError;
use super::vm_exception::VmException;
use crate::types::errors::program_errors::ProgramError;
use crate::vm::errors::{
    runner_errors::RunnerError, trace_errors::TraceError, vm_errors::VirtualMachineError,
};

#[derive(Debug, Error)]
pub enum CairoRunError {
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
    #[error(transparent)]
    Trace(#[from] TraceError),
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error(transparent)]
    VmException(Box<VmException>),
    #[error("Cairo Pie validation failed: {0}")]
    CairoPieValidation(#[from] CairoPieValidationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Test to catch possible enum size regressions
    fn test_cairo_run_error_size() {
        let size = crate::stdlib::mem::size_of::<CairoRunError>();
        assert!(size <= 32, "{size}")
    }
}

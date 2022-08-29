use crate::types::errors::program_errors::ProgramError;
use crate::vm::errors::{
    runner_errors::RunnerError, trace_errors::TraceError, vm_errors::VirtualMachineError,
};
use thiserror::Error;

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
}

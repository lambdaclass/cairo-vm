use crate::types::errors::program_errors::ProgramError;
use crate::vm::errors::{
    runner_errors::RunnerError, trace_errors::TraceError, vm_errors::VirtualMachineError,
};
use std::fmt;

#[derive(Debug)]
pub enum CairoRunError {
    Program(ProgramError),
    VirtualMachine(VirtualMachineError),
    Trace(TraceError),
    Runner(RunnerError),
}

impl fmt::Display for CairoRunError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CairoRunError::Program(error) => {
                write!(f, "Program failure: ")?;
                error.fmt(f)
            }
            CairoRunError::VirtualMachine(error) => {
                write!(f, "VM failure: ")?;
                error.fmt(f)
            }
            CairoRunError::Trace(error) => {
                write!(f, "Trace failure: ")?;
                error.fmt(f)
            }
            CairoRunError::Runner(error) => {
                write!(f, "Runner failure: ")?;
                error.fmt(f)
            }
        }
    }
}

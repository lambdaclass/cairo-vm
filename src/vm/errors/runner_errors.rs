use std::fmt;

#[derive(Debug, PartialEq)]
pub enum RunnerError {
    NoExecBase,
    NoExecBaseForEntrypoint,
    NoProgBase,
    MissingMain,
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
        }
    }
}

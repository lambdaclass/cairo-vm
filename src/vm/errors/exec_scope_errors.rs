use std::fmt;

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum ExecScopeError {
    ExitMainScopeError,
}

impl fmt::Display for ExecScopeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExecScopeError::ExitMainScopeError => {
                write!(f, "Cannot exit main scope.")
            }
        }
    }
}

use std::fmt;

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum ExecScopeError {
    ExitMainScopeError,
    NoScopeError,
}

impl fmt::Display for ExecScopeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExecScopeError::ExitMainScopeError => {
                write!(f, "Cannot exit main scope.")
            }
            ExecScopeError::NoScopeError => {
                write!(f, "Tried to access a scope that no longer exist. You may have called exit_scope()")
            }
        }
    }
}

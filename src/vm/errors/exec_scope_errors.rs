use thiserror::Error;

#[derive(Eq, Hash, PartialEq, Debug, Error)]
pub enum ExecScopeError {
    #[error("Cannot exit main scope.")]
    ExitMainScopeError,
    #[error("Tried to access a scope that no longer exist. You may have called exit_scope()")]
    NoScopeError,
}

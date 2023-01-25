use std::{fmt::Debug, io};

use felt::PRIME_STR;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ProgramError {
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Syntax(String),
    #[error("{0}")]
    Data(String),
    #[error("{0}")]
    Eof(String),
    #[error("Entrypoint {0} not found")]
    EntrypointNotFound(String),
    #[error("Constant {0} has no value")]
    ConstWithoutValue(String),
    #[error("Expected prime {PRIME_STR}, got {0}")]
    PrimeDiffers(String),
}

impl From<serde_json::Error> for ProgramError {
    fn from(error: serde_json::Error) -> ProgramError {
        match error.classify() {
            serde_json::error::Category::Io => ProgramError::Io(error.to_string()),
            serde_json::error::Category::Syntax => ProgramError::Syntax(error.to_string()),
            serde_json::error::Category::Data => ProgramError::Data(error.to_string()),
            serde_json::error::Category::Eof => ProgramError::Eof(error.to_string()),
        }
    }
}

impl From<io::Error> for ProgramError {
    fn from(error: io::Error) -> ProgramError {
        ProgramError::Io(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_entrypoint_not_found_error() {
        let error = ProgramError::EntrypointNotFound(String::from("my_function"));
        let formatted_error = format!("{}", error);
        assert_eq!(formatted_error, "Entrypoint my_function not found");
    }
}

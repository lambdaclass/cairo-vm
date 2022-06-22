use std::io;

#[derive(Debug)]
pub enum ProgramError {
    IO(io::Error),
    Parse(serde_json::Error),
}

impl From<serde_json::Error> for ProgramError {
    fn from(err: serde_json::Error) -> Self {
        ProgramError::Parse(err)
    }
}

impl From<io::Error> for ProgramError {
    fn from(err: io::Error) -> Self {
        ProgramError::IO(err)
    }
}

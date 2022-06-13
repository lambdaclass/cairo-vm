use std::fmt;

#[derive(Debug, PartialEq)]
pub enum TraceError {
    RegNotRelocatable,
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TraceError::RegNotRelocatable => write!(f, "Trace register must be relocatable"),
        }
    }
}

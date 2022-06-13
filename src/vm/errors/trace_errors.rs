use std::fmt;

#[derive(Debug, PartialEq)]
pub enum TraceError {
    _RegNotRelocatable,
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TraceError::_RegNotRelocatable => write!(f, "Trace register must be relocatable"),
        }
    }
}

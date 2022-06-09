use std::fmt;

pub enum BuiltinError {
    UninitializedBase,
}

impl fmt::Display for BuiltinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BuiltinError::UninitializedBase => write!(f, "Uninitialized self.base"),
        }
    }
}

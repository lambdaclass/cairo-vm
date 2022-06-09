use std::fmt;

pub enum BuiltinError {
    UninitializedBase,
    NumOutOfBounds,
    FoundNonInt,
}

impl fmt::Display for BuiltinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BuiltinError::UninitializedBase => write!(f, "Uninitialized self.base"),
            BuiltinError::NumOutOfBounds => write!(
                f,
                "Range-check validation failed, number is out of valid range"
            ),
            BuiltinError::FoundNonInt => write!(
                f,
                "Range-check validation failed, encountered non-int value"
            ),
        }
    }
}

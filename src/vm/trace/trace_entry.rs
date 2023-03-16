use crate::stdlib::prelude::*;

use crate::types::relocatable::Relocatable;
use serde::{Deserialize, Serialize};

///A trace entry for every instruction that was executed.
///Holds the register values before the instruction was executed.
#[derive(Debug, PartialEq, Eq)]
pub struct TraceEntry {
    pub pc: Relocatable,
    pub ap: Relocatable,
    pub fp: Relocatable,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocatedTraceEntry {
    pub ap: usize,
    pub fp: usize,
    pub pc: usize,
}

use crate::stdlib::prelude::*;
use serde::{Deserialize, Serialize};

///A trace entry for every instruction that was executed.
///Holds the register values before the instruction was executed.
/// Register values are represented as their offsets, as their indexes will always be 0,1,1 respectively
/// The index of the last pc will not be equal to 0, but it is not appended to the trace
#[derive(Debug, PartialEq, Eq)]
pub struct TraceEntry {
    pub pc_off: usize,
    pub ap_off: usize,
    pub fp_off: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocatedTraceEntry {
    pub ap: usize,
    pub fp: usize,
    pub pc: usize,
}

use crate::vm::builtin_runner::BuiltinRunner;
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::program::Program;
use crate::vm::relocatable::Relocatable;
use std::collections::HashMap;

pub struct CairoRunner {
    //Uses segment's memory as memory, in order to avoid maintaining two references to the same data
    program: Program,
    layout: String,
    builtin_runners: HashMap<String, BuiltinRunner>,
    pub segments: MemorySegmentManager,
    final_pc: Option<Relocatable>,
}

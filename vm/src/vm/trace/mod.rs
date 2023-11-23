pub mod trace_entry {
    use serde::{Deserialize, Serialize};

    ///A trace entry for every instruction that was executed.
    ///Holds the register values before the instruction was executed.
    ///Register values for ap & fp are represented as their offsets, as their indexes will always be 1
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct TraceEntry {
        pub pc: usize,
        pub ap: usize,
        pub fp: usize,
    }

    /// A trace entry for every instruction that was executed.
    /// Holds the register values before the instruction was executed, after going through the relocation process
    #[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
    pub struct RelocatedTraceEntry {
        pub pc: usize,
        pub ap: usize,
        pub fp: usize,
    }
}

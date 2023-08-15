use crate::types::program::StrippedProgram;
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use std::collections::HashMap;

use super::cairo_runner::ExecutionResources;

// Made up of (segment_index, segment_size)
pub type SegmentInfo = (isize, usize);

// A simplified version of Memory, without any additional data besides its elements
// Contains all addr-value pairs, ordered by index and offset
// Allows practical serialization + conversion between CairoPieMemory & Memory
// This conversion will remove all data besides the elements themselves
pub type CairoPieMemory = Vec<((usize, usize), MaybeRelocatable)>;

pub struct PublicMemoryPage {
    start: usize,
    size: usize,
}

// Hashmap value based on starknet/core/os/output.cairo usage
pub type Attributes = HashMap<String, Vec<usize>>;
pub type Pages = HashMap<usize, PublicMemoryPage>;
pub struct BuiltinAdditionalInfo {
    pages: Option<Pages>,
    attributes: Option<Attributes>,
    addresses: Option<Vec<Relocatable>>,
}
pub struct CairoPie {
    pub metadata: CairoPieMetadata,
    pub memory: CairoPieMemory,
    pub execution_resources: ExecutionResources,
}

pub struct CairoPieMetadata {
    pub program: StrippedProgram,
    pub program_segment: SegmentInfo,
    pub execution_segment: SegmentInfo,
    pub ret_fp_segment: SegmentInfo,
    pub ret_pc_segment: SegmentInfo,
    pub builtin_segments: HashMap<String, SegmentInfo>,
    pub extra_segments: Vec<SegmentInfo>,
}

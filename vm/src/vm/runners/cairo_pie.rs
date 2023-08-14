use std::collections::HashMap;

use crate::types::program::StrippedProgram;

// Made up of (segment_index, segment_size)
pub type SegmentInfo = (isize, usize);
pub struct CairoPie {
    pub metadata: CairoPieMetadata,
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

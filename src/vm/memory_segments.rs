use crate::vm::memory::Memory;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::Zero;
use std::collections::HashMap;

struct MemorySegmentManager {
    memory: Memory,
    prime: BigInt,
    num_segments: i32,
    segment_sizes: HashMap<BigInt, BigInt>,
    segment_used_sizes: Option<HashMap<BigInt, BigInt>>,
    public_memory_offsets: HashMap<BigInt, Vec<(BigInt, BigInt)>>,
    num_temp_segments: i32,
}

impl MemorySegmentManager {
    ///Adds a new segment and returns its starting location as a RelocatableValue.
    ///If size is not None the segment is finalized with the given size. (size will be always none for initialization)
    pub fn add(&mut self, size: Option<i32>) -> Relocatable {
        let segment_index = self.num_segments;
        self.num_segments += 1;
        if let Some(segment_size) = size {
            //TODO self.finalize(segment_index, size);
        }
        Relocatable {
            segment_index: BigInt::from_i32(segment_index).unwrap(),
            offset: BigInt::zero(),
        }
    }
}

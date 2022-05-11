use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::Zero;
use std::collections::HashMap;

pub struct MemorySegmentManager {
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
    ///Writes data into the memory at address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        ptr: &MaybeRelocatable,
        data: Vec<MaybeRelocatable>,
    ) -> MaybeRelocatable {
        for (num, value) in data.iter().enumerate() {
            self.memory.insert(
                &ptr.add_num_addr(BigInt::from_usize(num).unwrap(), None),
                value,
            );
        }
        ptr.add_num_addr(BigInt::from_usize(data.len()).unwrap(), None)
            .clone()
    }

    pub fn new(memory: Memory, prime: BigInt) -> MemorySegmentManager {
        MemorySegmentManager {
            memory: memory,
            prime: prime,
            num_segments: 0,
            segment_sizes: HashMap::<BigInt, BigInt>::new(),
            segment_used_sizes: None,
            public_memory_offsets: HashMap::<BigInt, Vec<(BigInt, BigInt)>>::new(),
            num_temp_segments: 0,
        }
    }
}

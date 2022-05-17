use crate::bigint;
use crate::relocatable;
use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;

pub struct MemorySegmentManager {
    pub memory: Memory,
    _prime: BigInt,
    pub num_segments: i32,
    _segment_sizes: HashMap<BigInt, BigInt>,
    _segment_used_sizes: Option<HashMap<BigInt, BigInt>>,
    _public_memory_offsets: HashMap<BigInt, Vec<(BigInt, BigInt)>>,
    _num_temp_segments: i32,
}

impl MemorySegmentManager {
    ///Adds a new segment and returns its starting location as a RelocatableValue.
    ///If size is not None the segment is finalized with the given size. (size will be always none for initialization)
    pub fn add(&mut self, size: Option<i32>) -> Relocatable {
        let segment_index = self.num_segments;
        self.num_segments += 1;
        if let Some(_segment_size) = size {
            //TODO self.finalize(segment_index, size);
        }
        relocatable!(segment_index, 0)
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

    pub fn new(prime: BigInt) -> MemorySegmentManager {
        MemorySegmentManager {
            memory: Memory::new(),
            _prime: prime,
            num_segments: 0,
            _segment_sizes: HashMap::<BigInt, BigInt>::new(),
            _segment_used_sizes: None,
            _public_memory_offsets: HashMap::<BigInt, Vec<(BigInt, BigInt)>>::new(),
            _num_temp_segments: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_segment_no_size() {
        let mut segments = MemorySegmentManager::new(bigint!(17));
        let base = segments.add(None);
        assert_eq!(base, relocatable!(0, 0));
        assert_eq!(segments.num_segments, 1);
    }

    #[test]
    fn add_segment_no_size_test_two_segments() {
        let mut segments = MemorySegmentManager::new(bigint!(17));
        let mut base = segments.add(None);
        base = segments.add(None);
        assert_eq!(
            base,
            Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(0)
            }
        );
        assert_eq!(segments.num_segments, 2);
    }

    #[test]
    fn load_data_empty() {
        let data = Vec::new();
        let ptr = MaybeRelocatable::RelocatableValue(relocatable!(0, 3));
        let mut segments = MemorySegmentManager::new(bigint!(17));
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(
            current_ptr,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 3))
        )
    }

    #[test]
    fn load_data_one_element() {
        let data = vec![MaybeRelocatable::Int(bigint!(4))];
        let ptr = MaybeRelocatable::RelocatableValue(relocatable!(0, 3));
        let mut segments = MemorySegmentManager::new(bigint!(17));
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(
            current_ptr,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 4))
        );
        assert_eq!(
            segments.memory.get(&ptr),
            Some(&MaybeRelocatable::Int(bigint!(4)))
        );
    }

    #[test]
    fn load_data_three_elements() {
        let data = vec![
            MaybeRelocatable::Int(bigint!(4)),
            MaybeRelocatable::Int(bigint!(5)),
            MaybeRelocatable::Int(bigint!(6)),
        ];
        let ptr = MaybeRelocatable::RelocatableValue(relocatable!(0, 3));
        let mut segments = MemorySegmentManager::new(bigint!(17));
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(
            current_ptr,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 6))
        );
        assert_eq!(
            segments.memory.get(&ptr),
            Some(&MaybeRelocatable::Int(bigint!(4)))
        );
        assert_eq!(
            segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 4))),
            Some(&MaybeRelocatable::Int(bigint!(5)))
        );
        assert_eq!(
            segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 5))),
            Some(&MaybeRelocatable::Int(bigint!(6)))
        );
    }
}

use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::Zero;
use std::collections::HashMap;

pub struct MemorySegmentManager {
    pub memory: Memory,
    prime: BigInt,
    pub num_segments: i32,
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

    pub fn new(prime: BigInt) -> MemorySegmentManager {
        MemorySegmentManager {
            memory: Memory::new(),
            prime: prime,
            num_segments: 0,
            segment_sizes: HashMap::<BigInt, BigInt>::new(),
            segment_used_sizes: None,
            public_memory_offsets: HashMap::<BigInt, Vec<(BigInt, BigInt)>>::new(),
            num_temp_segments: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_segment_no_size() {
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(17).unwrap());
        let base = segments.add(None);
        assert_eq!(
            base,
            Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            }
        );
        assert_eq!(segments.num_segments, 1);
    }

    #[test]
    fn add_segment_no_size_test_two_segments() {
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(17).unwrap());
        let mut base = segments.add(None);
        base = segments.add(None);
        assert_eq!(
            base,
            Relocatable {
                segment_index: BigInt::from_i32(1).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            }
        );
        assert_eq!(segments.num_segments, 2);
    }

    #[test]
    fn load_data_empty() {
        let data = Vec::new();
        let ptr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(0).unwrap(),
            offset: BigInt::from_i32(3).unwrap(),
        });
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(17).unwrap());
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(
            current_ptr,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(3).unwrap()
            })
        )
    }

    #[test]
    fn load_data_one_element() {
        let data = vec![MaybeRelocatable::Int(BigInt::from_i32(4).unwrap())];
        let ptr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(0).unwrap(),
            offset: BigInt::from_i32(3).unwrap(),
        });
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(17).unwrap());
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(
            current_ptr,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(4).unwrap()
            })
        );
        assert_eq!(
            segments.memory.get(&ptr),
            Some(&MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()))
        );
    }

    #[test]
    fn load_data_three_elements() {
        let data = vec![
            MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
        ];
        let ptr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(0).unwrap(),
            offset: BigInt::from_i32(3).unwrap(),
        });
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(17).unwrap());
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(
            current_ptr,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(6).unwrap()
            })
        );
        assert_eq!(
            segments.memory.get(&ptr),
            Some(&MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()))
        );
        assert_eq!(
            segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: BigInt::from_i32(0).unwrap(),
                    offset: BigInt::from_i32(4).unwrap()
                })),
            Some(&MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()))
        );
        assert_eq!(
            segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: BigInt::from_i32(0).unwrap(),
                    offset: BigInt::from_i32(5).unwrap()
                })),
            Some(&MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()))
        );
    }
}

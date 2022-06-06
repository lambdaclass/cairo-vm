use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::vm_memory::memory::Memory;

pub struct MemorySegmentManager {
    pub memory: Memory,
    pub num_segments: usize,
    segment_used_sizes: Option<Vec<usize>>,
}

#[allow(dead_code)]
impl MemorySegmentManager {
    ///Adds a new segment and returns its starting location as a RelocatableValue.
    ///If size is not None the segment is finalized with the given size. (size will be always none for initialization)
    pub fn add(&mut self, size: Option<usize>) -> Relocatable {
        let segment_index = self.num_segments;
        self.num_segments += 1;
        if let Some(_segment_size) = size {
            //TODO self.finalize(segment_index, size);
        }
        self.memory.data.push(Vec::new());
        Relocatable {
            segment_index,
            offset: 0,
        }
    }
    ///Writes data into the memory at address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        ptr: &MaybeRelocatable,
        data: Vec<MaybeRelocatable>,
    ) -> MaybeRelocatable {
        for (num, value) in data.iter().enumerate() {
            self.memory.insert(&ptr.add_usize_mod(num, None), value);
        }
        ptr.add_usize_mod(data.len(), None)
    }

    pub fn new() -> MemorySegmentManager {
        MemorySegmentManager {
            memory: Memory::new(),
            num_segments: 0,
            segment_used_sizes: None,
        }
    }

    ///Calculates the size (number of non-none elements) of each memory segment
    pub fn compute_effective_sizes(&mut self) {
        if self.segment_used_sizes != None {
            return;
        }
        let mut segment_used_sizes = Vec::new();
        for segment in self.memory.data.iter() {
            segment_used_sizes.push(segment.len());
        }
        self.segment_used_sizes = Some(segment_used_sizes);
    }

    ///Returns a vector that contains the first relocated address of each memory segment
    pub fn relocate_segments(&self) -> Vec<usize> {
        if self.segment_used_sizes == None {
            panic!("compute_effective_sizes should be called before relocate_segments");
        }
        let first_addr = 1;
        let mut relocation_table = Vec::new();
        relocation_table.push(first_addr);
        for (i, size) in self.segment_used_sizes.as_ref().unwrap().iter().enumerate() {
            relocation_table.push(relocation_table[i] + size);
        }
        relocation_table.pop();
        relocation_table
    }
}

#[cfg(test)]
mod tests {
    use crate::{bigint, relocatable};
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn add_segment_no_size() {
        let mut segments = MemorySegmentManager::new();
        let base = segments.add(None);
        assert_eq!(base, relocatable!(0, 0));
        assert_eq!(segments.num_segments, 1);
    }

    #[test]
    fn add_segment_no_size_test_two_segments() {
        let mut segments = MemorySegmentManager::new();
        let mut _base = segments.add(None);
        _base = segments.add(None);
        assert_eq!(
            _base,
            Relocatable {
                segment_index: 1,
                offset: 0
            }
        );
        assert_eq!(segments.num_segments, 2);
    }

    #[test]
    fn load_data_empty() {
        let data = Vec::new();
        let ptr = MaybeRelocatable::from((0, 3));
        let mut segments = MemorySegmentManager::new();
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(current_ptr, MaybeRelocatable::from((0, 3)))
    }

    #[test]
    fn load_data_one_element() {
        let data = vec![MaybeRelocatable::from(bigint!(4))];
        let ptr = MaybeRelocatable::from((0, 0));
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(current_ptr, MaybeRelocatable::from((0, 1)));
        assert_eq!(
            segments.memory.get(&ptr),
            Some(&MaybeRelocatable::from(bigint!(4)))
        );
    }

    #[test]
    fn load_data_three_elements() {
        let data = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(5)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        let ptr = MaybeRelocatable::from((0, 0));
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        let current_ptr = segments.load_data(&ptr, data);
        assert_eq!(current_ptr, MaybeRelocatable::from((0, 3)));

        assert_eq!(
            segments.memory.get(&ptr),
            Some(&MaybeRelocatable::from(bigint!(4)))
        );
        assert_eq!(
            segments.memory.get(&MaybeRelocatable::from((0, 1))),
            Some(&MaybeRelocatable::from(bigint!(5)))
        );
        assert_eq!(
            segments.memory.get(&MaybeRelocatable::from((0, 2))),
            Some(&MaybeRelocatable::from(bigint!(6)))
        );
    }
    #[test]
    fn compute_effective_sizes_for_one_segment_memory() {
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        segments.memory.insert(
            &MaybeRelocatable::from((0, 0)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 1)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 2)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.compute_effective_sizes();
        assert_eq!(Some(vec![3]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_one_segment_memory_with_gap() {
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        segments.memory.insert(
            &MaybeRelocatable::from((0, 6)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.compute_effective_sizes();
        assert_eq!(Some(vec![7]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_one_segment_memory_with_gaps() {
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        segments.memory.insert(
            &MaybeRelocatable::from((0, 3)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 4)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 7)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 9)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.compute_effective_sizes();
        assert_eq!(Some(vec![10]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_three_segment_memory() {
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        segments.add(None);
        segments.add(None);
        segments.memory.insert(
            &MaybeRelocatable::from((0, 0)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 1)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 2)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((1, 0)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((1, 1)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((1, 2)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((2, 0)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((2, 1)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((2, 2)),
            &MaybeRelocatable::from(bigint!(1)),
        );

        segments.compute_effective_sizes();
        assert_eq!(Some(vec![3, 3, 3]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_three_segment_memory_with_gaps() {
        let mut segments = MemorySegmentManager::new();
        segments.add(None);
        segments.add(None);
        segments.add(None);
        segments.memory.insert(
            &MaybeRelocatable::from((0, 2)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 5)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((0, 7)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((1, 1)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((2, 2)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((2, 4)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.memory.insert(
            &MaybeRelocatable::from((2, 7)),
            &MaybeRelocatable::from(bigint!(1)),
        );
        segments.compute_effective_sizes();
        assert_eq!(Some(vec![8, 2, 8]), segments.segment_used_sizes);
    }

    #[test]
    fn relocate_segments_one_segment() {
        let mut segments = MemorySegmentManager::new();
        segments.segment_used_sizes = Some(vec![3]);
        assert_eq!(segments.relocate_segments(), vec![1])
    }

    #[test]
    fn relocate_segments_five_segment() {
        let mut segments = MemorySegmentManager::new();
        segments.segment_used_sizes = Some(vec![3, 3, 56, 78, 8]);
        assert_eq!(segments.relocate_segments(), vec![1, 4, 7, 63, 141])
    }
}

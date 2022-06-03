use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::vm_memory::memory::Memory;

pub struct MemorySegmentManager {
    pub memory: Memory,
    pub num_segments: usize,
    segment_used_sizes: Option<Vec<usize>>,
}

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

    #[allow(dead_code)]
    pub fn compute_effective_sizes(&mut self) {
        if self.segment_used_sizes == None {
            return;
        }
        let mut segment_used_sizes = Vec::new();
        for segment in self.memory.data.iter() {
            segment_used_sizes.push(segment.len());
        }
        self.segment_used_sizes = Some(segment_used_sizes);
    }
}

#[cfg(test)]
mod tests {
    use crate::{bigint, relocatable};

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
}

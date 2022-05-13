use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use num_traits::FromPrimitive;

pub struct RangeCheckBuiltinRunner {
    included: bool,
    ratio: BigInt,
    base: Option<Relocatable>,
    stop_ptr: Option<Relocatable>,
    cells_per_instance: i32,
    n_input_cells: i32,
    inner_rc_bound: BigInt,
    bound: BigInt,
    n_parts: u32,
}
pub struct OutputRunner {
    included: bool,
    base: Option<Relocatable>,
    stop_ptr: Option<Relocatable>,
}

pub trait BuiltinRunner {
    ///Creates the necessary segments for the builtin in the MemorySegmentManager and stores the first address on the builtin's base
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager);
    fn initial_stack(&self) -> Vec<Relocatable>;
    ///Returns the builtin's base
    fn base(&self) -> Option<Relocatable>;
}

impl RangeCheckBuiltinRunner {
    pub fn new(included: bool, ratio: BigInt, n_parts: u32) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = BigInt::from_i32(2_i32.pow(16)).unwrap();
        RangeCheckBuiltinRunner {
            included: included,
            ratio: ratio,
            base: None,
            stop_ptr: None,
            cells_per_instance: 1,
            n_input_cells: 1,
            inner_rc_bound: inner_rc_bound.clone(),
            bound: inner_rc_bound.pow(n_parts),
            n_parts: n_parts,
        }
    }
}
impl BuiltinRunner for RangeCheckBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = Some(segments.add(None))
    }
    fn initial_stack(&self) -> Vec<Relocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![builtin_base.clone()]
            } else {
                panic!("Uninitialized self.base")
            }
        } else {
            Vec::new()
        }
    }

    fn base(&self) -> Option<Relocatable> {
        self.base.clone()
    }
}

impl OutputRunner {
    pub fn new(included: bool) -> OutputRunner {
        OutputRunner {
            included: included,
            base: None,
            stop_ptr: None,
        }
    }
}

impl BuiltinRunner for OutputRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = Some(segments.add(None))
    }

    fn initial_stack(&self) -> Vec<Relocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![builtin_base.clone()]
            } else {
                panic!("Uninitialized self.base")
            }
        } else {
            Vec::new()
        }
    }

    fn base(&self) -> Option<Relocatable> {
        self.base.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_segments_for_output() {
        let mut builtin = OutputRunner::new(true);
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(7).unwrap());
        builtin.initialize_segments(&mut segments);
        assert_eq!(
            builtin.base,
            Some(Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );
    }

    #[test]
    fn initialize_segments_for_range_check() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, BigInt::from_i32(8).unwrap(), 8);
        let mut segments = MemorySegmentManager::new(BigInt::from_i32(7).unwrap());
        builtin.initialize_segments(&mut segments);
        assert_eq!(
            builtin.base,
            Some(Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );
    }

    #[test]
    fn get_initial_stack_for_range_check_included_with_base() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, BigInt::from_i32(8).unwrap(), 8);
        builtin.base = Some(Relocatable {
            segment_index: BigInt::from_i32(1).unwrap(),
            offset: BigInt::from_i32(0).unwrap(),
        });
        let initial_stack = builtin.initial_stack();
        assert_eq!(Some(initial_stack[0].clone()), builtin.base());
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    #[should_panic]
    fn get_initial_stack_for_range_check_included_without_base() {
        let builtin = RangeCheckBuiltinRunner::new(true, BigInt::from_i32(8).unwrap(), 8);
        let _initial_stack = builtin.initial_stack();
    }

    #[test]
    fn get_initial_stack_for_range_check_not_included() {
        let  builtin = RangeCheckBuiltinRunner::new(false, BigInt::from_i32(8).unwrap(), 8);
        let initial_stack = builtin.initial_stack();
        assert_eq!(initial_stack.len(), 0);
    }

    #[test]
    fn get_initial_stack_for_output_included_with_base() {
        let mut builtin = OutputRunner::new(true);
        builtin.base = Some(Relocatable {
            segment_index: BigInt::from_i32(1).unwrap(),
            offset: BigInt::from_i32(0).unwrap(),
        });
        let initial_stack = builtin.initial_stack();
        assert_eq!(Some(initial_stack[0].clone()), builtin.base());
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    #[should_panic]
    fn get_initial_stack_for_output_included_without_base() {
        let builtin = OutputRunner::new(true);
        let initial_stack = builtin.initial_stack();
    }

    #[test]
    fn get_initial_stack_for_output_not_included() {
        let  builtin = OutputRunner::new(false);
        let initial_stack = builtin.initial_stack();
        assert_eq!(initial_stack.len(), 0);
    }
}

use crate::bigint;
use crate::vm::memory::Memory;
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use crate::vm::validated_memory_dict::ValidationRule;
use num_bigint::BigInt;
use num_traits::FromPrimitive;

pub struct RangeCheckBuiltinRunner {
    included: bool,
    _ratio: BigInt,
    base: Option<Relocatable>,
    _stop_ptr: Option<Relocatable>,
    _cells_per_instance: i32,
    _n_input_cells: i32,
    _inner_rc_bound: BigInt,
    bound: BigInt,
    _n_parts: u32,
}
pub struct OutputRunner {
    included: bool,
    base: Option<Relocatable>,
    _stop_ptr: Option<Relocatable>,
}

pub trait BuiltinRunner<'a> {
    ///Creates the necessary segments for the builtin in the MemorySegmentManager and stores the first address on the builtin's base
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager);
    fn initial_stack(&self) -> Vec<MaybeRelocatable>;
    ///Returns the builtin's base
    fn base(&self) -> Option<Relocatable>;
    fn validation_rule(&'a self) -> Option<ValidationRule<'a>>;
}

impl RangeCheckBuiltinRunner {
    pub fn new(included: bool, ratio: BigInt, n_parts: u32) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = bigint!(2_i32.pow(16));
        RangeCheckBuiltinRunner {
            included,
            _ratio: ratio,
            base: None,
            _stop_ptr: None,
            _cells_per_instance: 1,
            _n_input_cells: 1,
            _inner_rc_bound: inner_rc_bound.clone(),
            bound: inner_rc_bound.pow(n_parts),
            _n_parts: n_parts,
        }
    }
}
impl<'a> BuiltinRunner<'a> for RangeCheckBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = Some(segments.add(None))
    }
    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![MaybeRelocatable::RelocatableValue(builtin_base.clone())]
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

    fn validation_rule(&'a self) -> Option<ValidationRule<'a>> {
        let rule: ValidationRule<'a> = ValidationRule(Box::new(
            |memory: &Memory, address: MaybeRelocatable| -> MaybeRelocatable {
                let value = memory.get(&address);
                if let Some(MaybeRelocatable::Int(ref num)) = value {
                    if bigint!(0) <= num.clone() && num.clone() < self.bound {
                        address
                    } else {
                        panic!("Range-check validation failed, number is out of valid range")
                    }
                } else {
                    panic!("Range-check validation failed, encountered non-int value")
                }
            },
        ));
        Some(rule)
    }
}

impl OutputRunner {
    pub fn new(included: bool) -> OutputRunner {
        OutputRunner {
            included,
            base: None,
            _stop_ptr: None,
        }
    }
}

impl<'a> BuiltinRunner<'a> for OutputRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager) {
        self.base = Some(segments.add(None))
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![MaybeRelocatable::RelocatableValue(builtin_base.clone())]
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

    fn validation_rule(&'a self) -> Option<ValidationRule<'a>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relocatable;

    #[test]
    fn initialize_segments_for_output() {
        let mut builtin = OutputRunner::new(true);
        let mut segments = MemorySegmentManager::new(bigint!(7));
        builtin.initialize_segments(&mut segments);
        assert_eq!(builtin.base, Some(relocatable!(0, 0)));
    }

    #[test]
    fn initialize_segments_for_range_check() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let mut segments = MemorySegmentManager::new(bigint!(7));
        builtin.initialize_segments(&mut segments);
        assert_eq!(
            builtin.base,
            Some(Relocatable {
                segment_index: bigint!(0),
                offset: bigint!(0)
            })
        );
    }

    #[test]
    fn get_initial_stack_for_range_check_included_with_base() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        builtin.base = Some(relocatable!(1, 0));
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base().unwrap())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    #[should_panic]
    fn get_initial_stack_for_range_check_included_without_base() {
        let builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let _initial_stack = builtin.initial_stack();
    }

    #[test]
    fn get_initial_stack_for_range_check_not_included() {
        let builtin = RangeCheckBuiltinRunner::new(false, bigint!(8), 8);
        let initial_stack = builtin.initial_stack();
        assert_eq!(initial_stack.len(), 0);
    }

    #[test]
    fn get_initial_stack_for_output_included_with_base() {
        let mut builtin = OutputRunner::new(true);
        builtin.base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base().unwrap())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    #[should_panic]
    fn get_initial_stack_for_output_included_without_base() {
        let builtin = OutputRunner::new(true);
        let _initial_stack = builtin.initial_stack();
    }

    #[test]
    fn get_initial_stack_for_output_not_included() {
        let builtin = OutputRunner::new(false);
        let initial_stack = builtin.initial_stack();
        assert_eq!(initial_stack.len(), 0);
    }

    #[test]
    fn get_validation_rule_for_output() {
        let builtin = OutputRunner::new(false);
        let validation_rule = builtin.validation_rule();
        if let Some(_rule) = validation_rule {
            panic!("Test failed, rule should be None")
        }
    }
}

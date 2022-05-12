use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::relocatable::Relocatable;
use num_traits::FromPrimitive;
use num_bigint::BigInt;

pub struct RangeCheckBuiltinRunner {
    name: String,
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
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager);
    fn initial_stack(&self) -> Vec<Relocatable>;
}

impl RangeCheckBuiltinRunner {
    pub fn new(
        name: String,
        included: bool,
        ratio: BigInt,
        n_parts: u32
    ) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = BigInt::from_i32(2_i32.pow(16)).unwrap();
        RangeCheckBuiltinRunner {
            name: name,
            included: included,
            ratio: ratio,
            base: None,
            stop_ptr: None,
            cells_per_instance: 1,
            n_input_cells: 1,
            inner_rc_bound: inner_rc_bound.clone(),
            bound: inner_rc_bound.pow(n_parts),
            n_parts:n_parts,
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
}

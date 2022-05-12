use crate::vm::cairo_runner::CairoRunner;
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;

struct SimpleBuiltinRunner {
    name: String,
    included: bool,
    ratio: BigInt,
    base: Option<Relocatable>,
    stop_ptr: Option<Relocatable>,
    cells_per_instance: BigInt,
    n_input_cells: BigInt,
}
struct OutputRunner {
    included: bool,
    base: Option<Relocatable>,
    stop_ptr: Option<Relocatable>,
}

pub trait BuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager);
    fn initial_stack(&self) -> Vec<Relocatable>;
}

impl SimpleBuiltinRunner {
    pub fn new(
        name: String,
        included: bool,
        ratio: BigInt,
        cells_per_instance: BigInt,
        n_input_cells: BigInt,
    ) -> SimpleBuiltinRunner {
        SimpleBuiltinRunner {
            name: name,
            included: included,
            ratio: ratio,
            base: None,
            stop_ptr: None,
            cells_per_instance: cells_per_instance,
            n_input_cells: n_input_cells,
        }
    }
}
impl BuiltinRunner for SimpleBuiltinRunner {
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
    fn new(included: bool) -> OutputRunner {
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

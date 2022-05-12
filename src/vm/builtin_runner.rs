use crate::vm::cairo_runner::CairoRunner;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;

pub enum BuiltinRunner {
    SimpleBuiltinRunner,
    OutputRunner,
}

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

    pub fn initialize_segments(&mut self, runner: &mut CairoRunner) {
        self.base = Some(runner.segments.add(None))
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

    pub fn initialize_segments(&mut self, runner: &mut CairoRunner) {
        self.base = Some(runner.segments.add(None))
    }
}

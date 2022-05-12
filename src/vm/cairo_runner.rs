use crate::vm::builtin_runner::BuiltinRunner;
use crate::vm::builtin_runner::{OutputRunner, RangeCheckBuiltinRunner};
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::program::Program;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;

pub struct CairoRunner {
    //Uses segment's memory as memory, in order to avoid maintaining two references to the same data
    program: Program,
    layout: String,
    builtin_runners: HashMap<String, Box<dyn BuiltinRunner>>,
    pub segments: MemorySegmentManager,
    final_pc: Option<Relocatable>,
    program_base: Option<Relocatable>,
    execution_base: Option<Relocatable>,
}

impl CairoRunner {
    pub fn new(program: &Program) -> CairoRunner {
        let mut builtin_runners = HashMap::<String, Box<dyn BuiltinRunner>>::new();
        for builtin_name in program.builtins.iter() {
            if *builtin_name == String::from("output") {
                builtin_runners.insert(builtin_name.clone(), Box::new(OutputRunner::new(true)));
            }

            if *builtin_name == String::from("range_check") {
                //Information for Buitin info taken from here https://github.com/starkware-libs/cairo-lang/blob/b614d1867c64f3fb2cf4a4879348cfcf87c3a5a7/src/starkware/cairo/lang/instances.py#L115
                builtin_runners.insert(
                    builtin_name.clone(),
                    Box::new(RangeCheckBuiltinRunner::new(
                        builtin_name.clone(),
                        true,
                        BigInt::from_i32(8).unwrap(),
                        8,
                    )),
                );
            }
        }
        CairoRunner {
            program: program.clone(),
            layout: String::from("plain"),
            segments: MemorySegmentManager::new(program.prime.clone()),
            final_pc: None,
            program_base: None,
            execution_base: None,
            builtin_runners: builtin_runners,
        }
    }
    pub fn initialize_segments(&mut self, program_base: Option<Relocatable>) {
        self.program_base = match program_base {
            Some(base) => Some(base),
            None => Some(self.segments.add(None)),
        };
        self.execution_base = Some(self.segments.add(None));
        for (_key, builtin_runner) in self.builtin_runners.iter_mut() {
            builtin_runner.initialize_segments(&mut self.segments);
        }
    }
}

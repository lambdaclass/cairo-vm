use crate::vm::builtin_runner::{OutputRunner, SimpleBuiltinRunner};
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::program::Program;
use crate::vm::relocatable::Relocatable;
use crate::vm::builtin_runner::BuiltinRunner;
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
        };
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

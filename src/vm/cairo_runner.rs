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
    ///Creates the necessary segments for the program, execution, and each builtin on the MemorySegmentManager and stores the first adress of each of this new segments as each owner's base
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_segments_with_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::from_i32(17).unwrap(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        let program_base = Some(Relocatable {
            segment_index: BigInt::from_i32(5).unwrap(),
            offset: BigInt::from_i32(9).unwrap(),
        });
        cairo_runner.segments.num_segments = 6;
        cairo_runner.initialize_segments(program_base);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: BigInt::from_i32(5).unwrap(),
                offset: BigInt::from_i32(9).unwrap()
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: BigInt::from_i32(6).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );

        assert_eq!(
            cairo_runner.builtin_runners[&String::from("output")].base(),
            Some(Relocatable {
                segment_index: BigInt::from_i32(7).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );

        assert_eq!(cairo_runner.segments.num_segments, 8);
    }

    #[test]
    fn initialize_segments_no_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::from_i32(17).unwrap(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: BigInt::from_i32(0).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: BigInt::from_i32(1).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );

        assert_eq!(
            cairo_runner.builtin_runners[&String::from("output")].base(),
            Some(Relocatable {
                segment_index: BigInt::from_i32(2).unwrap(),
                offset: BigInt::from_i32(0).unwrap()
            })
        );

        assert_eq!(cairo_runner.segments.num_segments, 3);
    }
}

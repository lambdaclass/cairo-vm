use crate::bigint;
use crate::vm::builtin_runner::BuiltinRunner;
use crate::vm::builtin_runner::{OutputRunner, RangeCheckBuiltinRunner};
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::program::Program;
use crate::vm::relocatable::MaybeRelocatable;
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
    initial_ap: Option<Relocatable>,
    initial_fp: Option<Relocatable>,
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
                    Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
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
            initial_ap: None,
            initial_fp: None,
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

    fn initialize_state(&mut self, entrypoint: BigInt, stack: Vec<MaybeRelocatable>) {
        if let Some(prog_base) = self.program_base.clone() {
            let new_prog_base = Relocatable {
                segment_index: prog_base.segment_index,
                offset: prog_base.offset + entrypoint,
            };
            self.program_base = Some(new_prog_base.clone());
            self.segments.load_data(
                &MaybeRelocatable::RelocatableValue(new_prog_base),
                self.program.data.clone(),
            );
            if let Some(exec_base) = &self.execution_base {
                self.segments.load_data(
                    &MaybeRelocatable::RelocatableValue(exec_base.clone()),
                    stack,
                );
            } else {
                panic!("Cant initialize state without an execution base");
            }
        } else {
            panic!("Cant initialize state without a program base");
        }
    }

    fn initialize_function_entrypoint(
        &mut self,
        entrypoint: BigInt,
        mut stack: Vec<MaybeRelocatable>,
        return_fp: MaybeRelocatable,
    ) -> Relocatable {
        let end = self.segments.add(None);
        stack.append(&mut vec![
            return_fp,
            MaybeRelocatable::RelocatableValue(end.clone()),
        ]);
        if let Some(base) = &self.execution_base {
            self.initial_fp = Some(Relocatable {
                segment_index: base.segment_index.clone(),
                offset: base.offset.clone() + stack.len(),
            });
            self.initial_ap = self.initial_fp.clone();
        } else {
            panic!("Cant initialize the function entrypoint without a program base");
        }
        self.initialize_state(entrypoint, stack);
        self.final_pc = Some(end.clone());
        end
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
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        let program_base = Some(Relocatable {
            segment_index: bigint!(5),
            offset: bigint!(9),
        });
        cairo_runner.segments.num_segments = 6;
        cairo_runner.initialize_segments(program_base);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: bigint!(5),
                offset: bigint!(9),
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: bigint!(6),
                offset: bigint!(0),
            })
        );

        assert_eq!(
            cairo_runner.builtin_runners[&String::from("output")].base(),
            Some(Relocatable {
                segment_index: bigint!(7),
                offset: bigint!(0),
            })
        );

        assert_eq!(cairo_runner.segments.num_segments, 8);
    }

    #[test]
    fn initialize_segments_no_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: bigint!(0),
                offset: bigint!(0)
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(0)
            })
        );

        assert_eq!(
            cairo_runner.builtin_runners[&String::from("output")].base(),
            Some(Relocatable {
                segment_index: bigint!(2),
                offset: bigint!(0)
            })
        );

        assert_eq!(cairo_runner.segments.num_segments, 3);
    }

    #[test]
    fn initialize_state_empty_data_and_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: bigint!(2),
            offset: bigint!(0),
        });
        let stack = Vec::new();
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(1)
            })
        );
    }

    #[test]
    fn initialize_state_some_data_emty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::Int(bigint!(4)),
                MaybeRelocatable::Int(bigint!(6)),
            ],
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: bigint!(2),
            offset: bigint!(0),
        });
        let stack = Vec::new();
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(
                    cairo_runner.program_base.unwrap()
                )),
            Some(&MaybeRelocatable::Int(bigint!(4)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(2)
                })),
            Some(&MaybeRelocatable::Int(bigint!(6)))
        );
    }

    #[test]
    fn initialize_state_empty_data_some_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: bigint!(2),
            offset: bigint!(0),
        });
        let stack = vec![
            MaybeRelocatable::Int(bigint!(4)),
            MaybeRelocatable::Int(bigint!(6)),
        ];
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(
                    cairo_runner.execution_base.unwrap()
                )),
            Some(&MaybeRelocatable::Int(bigint!(4)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(2),
                    offset: bigint!(1)
                })),
            Some(&MaybeRelocatable::Int(bigint!(6)))
        );
    }

    #[test]
    #[should_panic]
    fn initialize_state_no_program_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: bigint!(2),
            offset: bigint!(0),
        });
        let stack = vec![
            MaybeRelocatable::Int(bigint!(4)),
            MaybeRelocatable::Int(bigint!(6)),
        ];
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
    }

    #[test]
    #[should_panic]
    fn initialize_state_no_execution_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        let stack = vec![
            MaybeRelocatable::Int(bigint!(4)),
            MaybeRelocatable::Int(bigint!(6)),
        ];
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
    }

    #[test]
    #[should_panic]
    fn initialize_function_entrypoint_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        let stack = Vec::new();
        let entrypoint = bigint!(1);
        let return_fp = MaybeRelocatable::Int(bigint!(9));
        cairo_runner.initialize_function_entrypoint(entrypoint, stack, return_fp);
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(
            cairo_runner.initial_fp,
            Some(Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(2)
            })
        );
    }
}

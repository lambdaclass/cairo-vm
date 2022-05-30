use crate::bigint;
use crate::vm::builtin_runner::{BuiltinRunner, OutputRunner, RangeCheckBuiltinRunner};
use crate::vm::memory_segments::MemorySegmentManager;
use crate::vm::program::Program;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;

pub struct CairoRunner {
    //Uses segment's memory as memory, in order to avoid maintaining two references to the same data
    program: Program,
    pub vm: VirtualMachine,
    _layout: String,
    pub segments: MemorySegmentManager,
    final_pc: Option<Relocatable>,
    program_base: Option<Relocatable>,
    execution_base: Option<Relocatable>,
    initial_ap: Option<Relocatable>,
    initial_fp: Option<Relocatable>,
    initial_pc: Option<Relocatable>,
}

#[allow(dead_code)]
impl CairoRunner {
    pub fn new(program: &Program) -> CairoRunner {
        let mut builtin_runners = HashMap::<String, Box<dyn BuiltinRunner>>::new();
        for builtin_name in program.builtins.iter() {
            if builtin_name == "output" {
                builtin_runners.insert(builtin_name.clone(), Box::new(OutputRunner::new(true)));
            }

            if builtin_name == "range_check" {
                //Information for Buitin info taken from here https://github.com/starkware-libs/cairo-lang/blob/b614d1867c64f3fb2cf4a4879348cfcf87c3a5a7/src/starkware/cairo/lang/instances.py#L115
                builtin_runners.insert(
                    builtin_name.clone(),
                    Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
                );
            }
        }
        //Initialize a vm, with empty values, will later be filled with actual data in initialize_vm
        CairoRunner {
            program: program.clone(),
            _layout: String::from("plain"),
            segments: MemorySegmentManager::new(program.prime.clone()),
            vm: VirtualMachine::new(program.prime.clone(), builtin_runners),
            final_pc: None,
            program_base: None,
            execution_base: None,
            initial_ap: None,
            initial_fp: None,
            initial_pc: None,
        }
    }
    ///Creates the necessary segments for the program, execution, and each builtin on the MemorySegmentManager and stores the first adress of each of this new segments as each owner's base
    pub fn initialize_segments(&mut self, program_base: Option<Relocatable>) {
        self.program_base = match program_base {
            Some(base) => Some(base),
            None => Some(self.segments.add(None)),
        };
        self.execution_base = Some(self.segments.add(None));
        for (_key, builtin_runner) in self.vm.builtin_runners.iter_mut() {
            builtin_runner.initialize_segments(&mut self.segments);
        }
    }

    fn initialize_state(&mut self, entrypoint: BigInt, stack: Vec<MaybeRelocatable>) {
        if let Some(prog_base) = self.program_base.clone() {
            let initial_pc = Relocatable {
                segment_index: prog_base.clone().segment_index,
                offset: prog_base.clone().offset + entrypoint,
            };
            self.initial_pc = Some(initial_pc);
            self.segments.load_data(
                &MaybeRelocatable::RelocatableValue(prog_base),
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
            panic!("Cant initialize the function entrypoint without an execution base");
        }
        self.initialize_state(entrypoint, stack);
        self.final_pc = Some(end.clone());
        end
    }
    ///Initializes state for running a program from the main() entrypoint.
    ///If self.proof_mode == True, the execution starts from the start label rather then the main() function.
    ///Returns the value of the program counter after returning from main.
    pub fn initialize_main_entrypoint(&mut self) -> Relocatable {
        //self.execution_public_memory = Vec::new() -> Not used now
        let mut stack = Vec::new();
        for (_name, builtin_runner) in self.vm.builtin_runners.iter() {
            stack.append(&mut builtin_runner.initial_stack());
        }
        //Different process if proof_mode is enabled
        let return_fp = self.segments.add(None);
        if let Some(main) = &self.program.main {
            let main_clone = main.clone();
            self.initialize_function_entrypoint(
                main_clone,
                stack,
                MaybeRelocatable::RelocatableValue(return_fp),
            )
        } else {
            panic!("Missing main()")
        }
    }

    pub fn initialize_vm(&mut self) {
        //TODO hint_locals and static_locals
        self.vm.run_context.pc =
            MaybeRelocatable::RelocatableValue(self.initial_pc.clone().unwrap());
        self.vm.run_context.ap =
            MaybeRelocatable::RelocatableValue(self.initial_ap.clone().unwrap());
        self.vm.run_context.fp =
            MaybeRelocatable::RelocatableValue(self.initial_fp.clone().unwrap());
        self.vm.run_context.memory = self.segments.memory.clone();
        self.vm._program_base = Some(MaybeRelocatable::RelocatableValue(
            self.program_base.clone().unwrap(),
        ));
        self.vm.validated_memory.memory = self.segments.memory.clone();
        for (_key, builtin) in self.vm.builtin_runners.iter() {
            let vec = builtin.validate_existing_memory(&self.vm.validated_memory.memory);
            if let Some(mut validated_addresses) = vec {
                self.vm
                    .validated_memory
                    .validated_addresses
                    .append(&mut validated_addresses)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relocatable;

    #[test]
    fn initialize_segments_with_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
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
            cairo_runner.vm.builtin_runners[&String::from("output")].base(),
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
            main: None,
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
            cairo_runner.vm.builtin_runners[&String::from("output")].base(),
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
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(1, 0));
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = Vec::new();
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
        assert_eq!(
            cairo_runner.initial_pc,
            Some(Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(1)
            })
        );
    }

    #[test]
    fn initialize_state_some_data_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::Int(bigint!(4)),
                MaybeRelocatable::Int(bigint!(6)),
            ],
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(Relocatable {
            segment_index: bigint!(1),
            offset: bigint!(0),
        });
        cairo_runner.execution_base = Some(relocatable!(2, 0));
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
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))),
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
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(1, 0));
        cairo_runner.execution_base = Some(relocatable!(2, 0));
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
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(2, 1))),
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
            main: None,
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
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(1, 0));
        let stack = vec![
            MaybeRelocatable::Int(bigint!(4)),
            MaybeRelocatable::Int(bigint!(6)),
        ];
        let entrypoint = bigint!(1);
        cairo_runner.initialize_state(entrypoint, stack);
    }

    #[test]
    fn initialize_function_entrypoint_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(1, 0));
        let stack = Vec::new();
        let entrypoint = bigint!(0);
        let return_fp = MaybeRelocatable::Int(bigint!(9));
        cairo_runner.initialize_function_entrypoint(entrypoint, stack, return_fp);
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(cairo_runner.initial_fp, Some(relocatable!(1, 2)));
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))),
            Some(&MaybeRelocatable::Int(bigint!(9)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(0, 0)))
        );
    }

    #[test]
    fn initialize_function_entrypoint_some_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(1, 0));
        let stack = vec![MaybeRelocatable::Int(bigint!(7))];
        let entrypoint = bigint!(1);
        let return_fp = MaybeRelocatable::Int(bigint!(9));
        cairo_runner.initialize_function_entrypoint(entrypoint, stack, return_fp);
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(cairo_runner.initial_fp, Some(relocatable!(1, 3)));
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))),
            Some(&MaybeRelocatable::Int(bigint!(7)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))),
            Some(&MaybeRelocatable::Int(bigint!(9)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 2))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(0, 0)))
        );
    }

    #[test]
    #[should_panic]
    fn initialize_function_entrypoint_no_execution_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        let stack = vec![MaybeRelocatable::Int(bigint!(7))];
        let entrypoint = bigint!(1);
        let return_fp = MaybeRelocatable::Int(bigint!(9));
        cairo_runner.initialize_function_entrypoint(entrypoint, stack, return_fp);
    }

    #[test]
    #[should_panic]
    fn initialize_main_entrypoint_no_main() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_main_entrypoint();
    }

    #[test]
    fn initialize_main_entrypoint() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(bigint!(1)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(0, 0));
        let return_pc = cairo_runner.initialize_main_entrypoint();
        assert_eq!(return_pc, relocatable!(1, 0));
    }

    #[test]
    fn initialize_vm_no_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(bigint!(1)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_vm();
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 1))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 2))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 2))
        );
        assert_eq!(
            cairo_runner.vm._program_base,
            Some(MaybeRelocatable::RelocatableValue(relocatable!(0, 0)))
        );
    }

    #[test]
    fn initialize_vm_with_range_check_valid() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(bigint!(1)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_segments(None);
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::RelocatableValue(relocatable!(2, 1)),
            &MaybeRelocatable::Int(bigint!(23)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::RelocatableValue(relocatable!(2, 4)),
            &MaybeRelocatable::Int(bigint!(233)),
        );
        cairo_runner.initialize_vm();
        assert_eq!(
            cairo_runner.vm.builtin_runners[&String::from("range_check")].base(),
            Some(relocatable!(2, 0))
        );
        assert!(cairo_runner
            .vm
            .validated_memory
            .validated_addresses
            .contains(&MaybeRelocatable::RelocatableValue(relocatable!(2, 1))));
        assert!(cairo_runner
            .vm
            .validated_memory
            .validated_addresses
            .contains(&MaybeRelocatable::RelocatableValue(relocatable!(2, 4))));
        assert_eq!(
            cairo_runner.vm.validated_memory.validated_addresses.len(),
            2
        );
    }

    #[test]
    #[should_panic]
    fn initialize_vm_with_range_check_invalid() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(bigint!(1)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_segments(None);
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::RelocatableValue(relocatable!(2, 1)),
            &MaybeRelocatable::Int(bigint!(23)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::RelocatableValue(relocatable!(2, 4)),
            &MaybeRelocatable::Int(bigint!(-1)),
        );
        cairo_runner.initialize_vm();
    }
}

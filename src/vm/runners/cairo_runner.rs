use crate::bigint;
use crate::types::program::Program;
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::runners::builtin_runner::{BuiltinRunner, OutputRunner, RangeCheckBuiltinRunner};
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_core::VirtualMachineError;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;

pub struct CairoRunner {
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
        self.vm.memory = self.segments.memory.clone();
        self.vm._program_base = Some(MaybeRelocatable::RelocatableValue(
            self.program_base.clone().unwrap(),
        ));
        self.vm.memory = self.segments.memory.clone();
        for (_key, builtin) in self.vm.builtin_runners.iter() {
            let vec = builtin.validate_existing_memory(&self.vm.memory);
            if let Some(mut validated_addresses) = vec {
                self.vm.validated_addresses.append(&mut validated_addresses)
            }
        }
    }

    pub fn run_until_pc(&mut self, address: MaybeRelocatable) -> Result<(), VirtualMachineError> {
        while self.vm.run_context.pc != address {
            self.vm.step()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;
    use crate::relocatable;
    use crate::vm::trace::trace_entry::TraceEntry;

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
            .validated_addresses
            .contains(&MaybeRelocatable::RelocatableValue(relocatable!(2, 1))));
        assert!(cairo_runner
            .vm
            .validated_addresses
            .contains(&MaybeRelocatable::RelocatableValue(relocatable!(2, 4))));
        assert_eq!(cairo_runner.vm.validated_addresses.len(), 2);
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

    //Integration tests for initialization phase

    #[test]
    /*Program used:
    func myfunc(a: felt) -> (r: felt):
        let b = a * 2
        return(b)
    end

    func main():
        let a = 1
        let b = myfunc(a)
        return()
    end

    main = 3
    data = [5207990763031199744, 2, 2345108766317314046, 5189976364521848832, 1, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020476, 2345108766317314046]
    */
    fn initialization_phase_no_builtins() {
        let program = Program {
            builtins: vec![],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::Int(BigInt::from_i64(5207990763031199744).unwrap()),
                MaybeRelocatable::Int(bigint!(2)),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(bigint!(1)),
                MaybeRelocatable::Int(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967292, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(bigint!(3)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(3, 0)));

        //RunContext check
        //Registers
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 3))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 2))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 2))
        );
        //Memory
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 0))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5207990763031199744).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 1))),
            Some(&MaybeRelocatable::Int(bigint!(2)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 2))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 3))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 4))),
            Some(&MaybeRelocatable::Int(bigint!(1)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 5))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(1226245742482522112).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 6))),
            Some(&MaybeRelocatable::Int(BigInt::new(
                Sign::Plus,
                vec![
                    4294967292, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                    134217728,
                ],
            )))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 7))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(2, 0)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(3, 0)))
        );
    }

    #[test]
    /*Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        return()
    end

    main = 4
    data = [4612671182993129469, 5198983563776393216, 1, 2345108766317314046, 5191102247248822272, 5189976364521848832, 1, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020474, 2345108766317314046]
    */
    fn initialization_phase_output_builtin() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::Int(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::Int(bigint!(1)),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(bigint!(1)),
                MaybeRelocatable::Int(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967290, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(bigint!(4)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(4, 0)));

        //RunContext check
        //Registers
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 4))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 3))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 3))
        );
        //Memory
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 0))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(4612671182993129469).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 1))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5198983563776393216).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 2))),
            Some(&MaybeRelocatable::Int(bigint!(1)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 3))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 4))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5191102247248822272).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 5))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 6))),
            Some(&MaybeRelocatable::Int(bigint!(1)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 7))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(1226245742482522112).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 8))),
            Some(&MaybeRelocatable::Int(BigInt::new(
                Sign::Plus,
                vec![
                    4294967290, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                    134217728
                ]
            )))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 9))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(2, 0)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(3, 0)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 2))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(4, 0)))
        );
    }

    #[test]
    /*Program used:
    %builtins range_check

    func check_range{range_check_ptr}(num):

        # Check that 0 <= num < 2**64.
        [range_check_ptr] = num
        assert [range_check_ptr + 1] = 2 ** 64 - 1 - num
        let range_check_ptr = range_check_ptr + 2
        return()
    end

    func main{range_check_ptr}():
        check_range(7)
        return()
    end

    main = 8
    data = [4612671182993129469, 5189976364521848832, 18446744073709551615, 5199546496550207487, 4612389712311386111, 5198983563776393216, 2, 2345108766317314046, 5191102247248822272, 5189976364521848832, 7, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020470, 2345108766317314046]
    */
    fn initialization_phase_range_check_builtin() {
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::Int(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i128(18446744073709551615).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5199546496550207487).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(4612389712311386111).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::Int(bigint!(2)),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(bigint!(7)),
                MaybeRelocatable::Int(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967286, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(bigint!(8)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(4, 0)));

        //RunContext check
        //Registers
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::RelocatableValue(relocatable!(0, 8))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 3))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::RelocatableValue(relocatable!(1, 3))
        );
        //Memory
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 0))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(4612671182993129469).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 1))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 2))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i128(18446744073709551615).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 3))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5199546496550207487).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 4))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(4612389712311386111).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 5))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5198983563776393216).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 6))),
            Some(&MaybeRelocatable::Int(bigint!(2)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 7))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 8))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5191102247248822272).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 9))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 10))),
            Some(&MaybeRelocatable::Int(bigint!(7)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 11))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(1226245742482522112).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 12))),
            Some(&MaybeRelocatable::Int(BigInt::new(
                Sign::Plus,
                vec![
                    4294967286, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                    134217728
                ]
            )))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(0, 13))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(2, 0)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(3, 0)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 2))),
            Some(&MaybeRelocatable::RelocatableValue(relocatable!(4, 0)))
        );
    }

    //Integration tests for initialization + execution phase

    #[test]
    /*Program used:
    func myfunc(a: felt) -> (r: felt):
        let b = a * 2
        return(b)
    end

    func main():
        let a = 1
        let b = myfunc(a)
        return()
    end

    main = 3
    data = [5207990763031199744, 2, 2345108766317314046, 5189976364521848832, 1, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020476, 2345108766317314046]
    */
    fn initialize_and_run_function_call() {
        //Initialization Phase
        let program = Program {
            builtins: vec![],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::Int(BigInt::from_i64(5207990763031199744).unwrap()),
                MaybeRelocatable::Int(bigint!(2)),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(bigint!(1)),
                MaybeRelocatable::Int(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967292, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(bigint!(3)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        assert_eq!(end, relocatable!(3, 0));
        cairo_runner.initialize_vm();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: bigint!(3),
                offset: bigint!(0)
            })
        );

        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(6)
            })
        );

        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: bigint!(2),
                offset: bigint!(0)
            })
        );

        //Check each TraceEntry in trace
        assert_eq!(cairo_runner.vm.trace.len(), 5);
        assert_eq!(
            cairo_runner.vm.trace[0],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(3)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(2)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(2)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[1],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(5)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(3)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(2)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[2],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(0)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(5)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(5)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[3],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(2)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(6)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(5)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[4],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(7)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(6)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(2)
                }),
            }
        );
    }

    #[test]
    /*Program used:
    %builtins range_check

    func check_range{range_check_ptr}(num):

        # Check that 0 <= num < 2**64.
        [range_check_ptr] = num
        assert [range_check_ptr + 1] = 2 ** 64 - 1 - num
        let range_check_ptr = range_check_ptr + 2
        return()
    end

    func main{range_check_ptr}():
        check_range(7)
        return()
    end

    main = 8
    data = [4612671182993129469, 5189976364521848832, 18446744073709551615, 5199546496550207487, 4612389712311386111, 5198983563776393216, 2, 2345108766317314046, 5191102247248822272, 5189976364521848832, 7, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020470, 2345108766317314046]
    */
    fn initializae_and_run_range_check_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::Int(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i128(18446744073709551615).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5199546496550207487).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(4612389712311386111).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::Int(bigint!(2)),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(bigint!(7)),
                MaybeRelocatable::Int(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967286, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(bigint!(8)),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: bigint!(4),
                offset: bigint!(0)
            })
        );

        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: bigint!(1),
                offset: bigint!(10)
            })
        );

        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index: bigint!(3),
                offset: bigint!(0)
            })
        );

        //Check each TraceEntry in trace
        assert_eq!(cairo_runner.vm.trace.len(), 10);
        assert_eq!(
            cairo_runner.vm.trace[0],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(8)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(3)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(3)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[1],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(9)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(4)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(3)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[2],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(11)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(5)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(3)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[3],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(0)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[4],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(1)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[5],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(3)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(8)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[6],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(4)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(9)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[7],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(5)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(9)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[8],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(7)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(10)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(7)
                }),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[9],
            TraceEntry {
                pc: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(0),
                    offset: bigint!(13)
                }),
                ap: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(10)
                }),
                fp: MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: bigint!(1),
                    offset: bigint!(3)
                }),
            }
        );
    }
}

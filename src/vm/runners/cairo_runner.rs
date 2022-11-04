use crate::{
    hint_processor::hint_processor_definition::{HintProcessor, HintReference},
    math_utils::safe_div_usize,
    types::{
        exec_scope::ExecutionScopes,
        instruction::Register,
        layout::CairoLayout,
        program::Program,
        relocatable::{relocate_value, MaybeRelocatable, Relocatable},
    },
    utils::{is_subsequence, to_field_element},
    vm::{
        errors::{
            memory_errors::MemoryError, runner_errors::RunnerError, trace_errors::TraceError,
            vm_errors::VirtualMachineError,
        },
        security::verify_secure_runner,
        {
            runners::builtin_runner::{
                BitwiseBuiltinRunner, BuiltinRunner, EcOpBuiltinRunner, HashBuiltinRunner,
                OutputBuiltinRunner, RangeCheckBuiltinRunner,
            },
            trace::trace_entry::{relocate_trace_register, RelocatedTraceEntry},
            vm_core::VirtualMachine,
        },
    },
};
use num_bigint::BigInt;
use std::{
    any::Any,
    collections::{HashMap, HashSet},
    io,
};

pub struct CairoRunner {
    pub(crate) program: Program,
    layout: CairoLayout,
    final_pc: Option<Relocatable>,
    pub(crate) program_base: Option<Relocatable>,
    execution_base: Option<Relocatable>,
    initial_ap: Option<Relocatable>,
    initial_fp: Option<Relocatable>,
    initial_pc: Option<Relocatable>,
    accessed_addresses: Option<HashSet<Relocatable>>,
    run_ended: bool,
    pub original_steps: Option<usize>,
    pub relocated_memory: Vec<Option<BigInt>>,
    pub relocated_trace: Option<Vec<RelocatedTraceEntry>>,
    pub exec_scopes: ExecutionScopes,
}

impl CairoRunner {
    pub fn new(program: &Program, layout: &str) -> Result<CairoRunner, RunnerError> {
        let cairo_layout = match layout {
            "plain" => CairoLayout::plain_instance(),
            "small" => CairoLayout::small_instance(),
            "dex" => CairoLayout::dex_instance(),
            "perpetual_with_bitwise" => CairoLayout::perpetual_with_bitwise_instance(),
            "bitwise" => CairoLayout::bitwise_instance(),
            "recursive" => CairoLayout::recursive_instance(),
            "all" => CairoLayout::all_instance(),
            name => return Err(RunnerError::InvalidLayoutName(name.to_string())),
        };
        Ok(CairoRunner {
            program: program.clone(),
            layout: cairo_layout,
            final_pc: None,
            program_base: None,
            execution_base: None,
            initial_ap: None,
            initial_fp: None,
            initial_pc: None,
            accessed_addresses: None,
            run_ended: false,
            original_steps: None,
            relocated_memory: Vec::new(),
            relocated_trace: None,
            exec_scopes: ExecutionScopes::new(),
        })
    }

    pub fn initialize(&mut self, vm: &mut VirtualMachine) -> Result<Relocatable, RunnerError> {
        self.initialize_builtins(vm)?;
        self.initialize_segments(vm, None);
        let end = self.initialize_main_entrypoint(vm)?;
        self.initialize_vm(vm)?;
        Ok(end)
    }

    fn initialize_builtins(&self, vm: &mut VirtualMachine) -> Result<(), RunnerError> {
        let builtin_ordered_list = vec![
            String::from("output"),
            String::from("pedersen"),
            String::from("range_check"),
            String::from("ecdsa"),
            String::from("bitwise"),
            String::from("ec_op"),
        ];
        if !is_subsequence(&self.program.builtins, &builtin_ordered_list) {
            return Err(RunnerError::DisorderedBuiltins);
        };
        let no_builtin_error = |builtin_name: &str| {
            RunnerError::NoBuiltinForInstance(builtin_name.to_string(), self.layout.name.clone())
        };
        let mut builtin_runners = Vec::<(String, BuiltinRunner)>::new();
        for builtin_name in self.program.builtins.iter() {
            if builtin_name == "output" {
                builtin_runners.push((builtin_name.clone(), OutputBuiltinRunner::new().into()));
            }

            if builtin_name == "pedersen" {
                builtin_runners.push((
                    builtin_name.clone(),
                    HashBuiltinRunner::new(
                        self.layout
                            .builtins
                            .pedersen
                            .as_ref()
                            .ok_or_else(|| no_builtin_error(builtin_name))?
                            .ratio
                            .to_owned(),
                    )
                    .into(),
                ));
            }

            if builtin_name == "range_check" {
                let range_check_instance = self
                    .layout
                    .builtins
                    .range_check
                    .as_ref()
                    .ok_or_else(|| no_builtin_error(builtin_name))?;
                builtin_runners.push((
                    builtin_name.clone(),
                    RangeCheckBuiltinRunner::new(
                        range_check_instance.ratio,
                        range_check_instance.n_parts,
                    )
                    .into(),
                ));
            }
            if builtin_name == "bitwise" {
                builtin_runners.push((
                    builtin_name.clone(),
                    BitwiseBuiltinRunner::new(
                        self.layout
                            .builtins
                            .bitwise
                            .as_ref()
                            .ok_or_else(|| no_builtin_error(builtin_name))?,
                    )
                    .into(),
                ));
            }
            if builtin_name == "ec_op" {
                builtin_runners.push((
                    builtin_name.clone(),
                    EcOpBuiltinRunner::new(
                        self.layout
                            .builtins
                            .ec_op
                            .as_ref()
                            .ok_or_else(|| no_builtin_error(builtin_name))?,
                    )
                    .into(),
                ));
            }
        }
        vm.builtin_runners = builtin_runners;
        Ok(())
    }
    ///Creates the necessary segments for the program, execution, and each builtin on the MemorySegmentManager and stores the first adress of each of this new segments as each owner's base
    fn initialize_segments(&mut self, vm: &mut VirtualMachine, program_base: Option<Relocatable>) {
        self.program_base = match program_base {
            Some(base) => Some(base),
            None => Some(vm.segments.add(&mut vm.memory)),
        };
        self.execution_base = Some(vm.segments.add(&mut vm.memory));
        for (_key, builtin_runner) in vm.builtin_runners.iter_mut() {
            builtin_runner.initialize_segments(&mut vm.segments, &mut vm.memory);
        }
    }

    fn initialize_state(
        &mut self,
        vm: &mut VirtualMachine,
        entrypoint: usize,
        stack: Vec<MaybeRelocatable>,
    ) -> Result<(), RunnerError> {
        if let Some(prog_base) = self.program_base.clone() {
            let initial_pc = Relocatable {
                segment_index: prog_base.segment_index,
                offset: prog_base.offset + entrypoint,
            };
            self.initial_pc = Some(initial_pc);
            vm.segments
                .load_data(
                    &mut vm.memory,
                    &MaybeRelocatable::RelocatableValue(prog_base),
                    self.program.data.clone(),
                )
                .map_err(RunnerError::MemoryInitializationError)?;
        }
        if let Some(exec_base) = &self.execution_base {
            vm.segments
                .load_data(
                    &mut vm.memory,
                    &MaybeRelocatable::RelocatableValue(exec_base.clone()),
                    stack,
                )
                .map_err(RunnerError::MemoryInitializationError)?;
        } else {
            return Err(RunnerError::NoProgBase);
        }
        Ok(())
    }

    fn initialize_function_entrypoint(
        &mut self,
        vm: &mut VirtualMachine,
        entrypoint: usize,
        mut stack: Vec<MaybeRelocatable>,
        return_fp: MaybeRelocatable,
    ) -> Result<Relocatable, RunnerError> {
        let end = vm.segments.add(&mut vm.memory);
        stack.append(&mut vec![
            return_fp,
            MaybeRelocatable::RelocatableValue(end.clone()),
        ]);
        if let Some(base) = &self.execution_base {
            self.initial_fp = Some(Relocatable {
                segment_index: base.segment_index,
                offset: base.offset + stack.len(),
            });
            self.initial_ap = self.initial_fp.clone();
        } else {
            return Err(RunnerError::NoExecBaseForEntrypoint);
        }
        self.initialize_state(vm, entrypoint, stack)?;
        self.final_pc = Some(end.clone());
        Ok(end)
    }

    ///Initializes state for running a program from the main() entrypoint.
    ///If self.proof_mode == True, the execution starts from the start label rather then the main() function.
    ///Returns the value of the program counter after returning from main.
    fn initialize_main_entrypoint(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> Result<Relocatable, RunnerError> {
        //self.execution_public_memory = Vec::new() -> Not used now
        let mut stack = Vec::new();
        for (_name, builtin_runner) in vm.builtin_runners.iter() {
            stack.append(&mut builtin_runner.initial_stack());
        }
        //Different process if proof_mode is enabled
        let return_fp = vm.segments.add(&mut vm.memory);
        if let Some(main) = &self.program.main {
            let main_clone = *main;
            Ok(self.initialize_function_entrypoint(
                vm,
                main_clone,
                stack,
                MaybeRelocatable::RelocatableValue(return_fp),
            )?)
        } else {
            Err(RunnerError::MissingMain)
        }
    }

    fn initialize_vm(&mut self, vm: &mut VirtualMachine) -> Result<(), RunnerError> {
        vm.run_context.pc = self.initial_pc.as_ref().ok_or(RunnerError::NoPC)?.clone();
        vm.run_context.ap = self.initial_ap.as_ref().ok_or(RunnerError::NoAP)?.offset;
        vm.run_context.fp = self.initial_fp.as_ref().ok_or(RunnerError::NoFP)?.offset;
        vm._program_base = Some(MaybeRelocatable::from(
            self.program_base.as_ref().ok_or(RunnerError::NoProgBase)?,
        ));
        for (_, builtin) in vm.builtin_runners.iter() {
            builtin.add_validation_rule(&mut vm.memory)?;
        }
        vm.memory
            .validate_existing_memory()
            .map_err(RunnerError::MemoryValidationError)
    }

    pub fn get_reference_list(&self) -> HashMap<usize, HintReference> {
        let mut references = HashMap::<usize, HintReference>::new();

        for (i, reference) in self.program.reference_manager.references.iter().enumerate() {
            references.insert(
                i,
                HintReference {
                    register: reference.value_address.register.clone(),
                    offset1: reference.value_address.offset1,
                    offset2: reference.value_address.offset2,
                    inner_dereference: reference.value_address.inner_dereference,
                    dereference: reference.value_address.dereference,
                    immediate: reference.value_address.immediate.clone(),
                    // only store `ap` tracking data if the reference is referred to it
                    ap_tracking_data: if reference.value_address.register == Some(Register::FP) {
                        None
                    } else {
                        Some(reference.ap_tracking_data.clone())
                    },
                    cairo_type: Some(reference.value_address.value_type.clone()),
                },
            );
        }
        references
    }

    /// Gets the data used by the HintProcessor to execute each hint
    pub fn get_hint_data_dictionary(
        &self,
        references: &HashMap<usize, HintReference>,
        hint_executor: &dyn HintProcessor,
    ) -> Result<HashMap<usize, Vec<Box<dyn Any>>>, VirtualMachineError> {
        let mut hint_data_dictionary = HashMap::<usize, Vec<Box<dyn Any>>>::new();
        for (hint_index, hints) in self.program.hints.iter() {
            for hint in hints {
                let hint_data = hint_executor.compile_hint(
                    &hint.code,
                    &hint.flow_tracking_data.ap_tracking,
                    &hint.flow_tracking_data.reference_ids,
                    references,
                );
                hint_data_dictionary
                    .entry(*hint_index)
                    .or_insert(vec![])
                    .push(
                        hint_data
                            .map_err(|_| VirtualMachineError::CompileHintFail(hint.code.clone()))?,
                    );
            }
        }
        Ok(hint_data_dictionary)
    }

    pub fn get_constants(&self) -> &HashMap<String, BigInt> {
        &self.program.constants
    }

    pub fn run_until_pc(
        &mut self,
        address: Relocatable,
        vm: &mut VirtualMachine,
        hint_processor: &dyn HintProcessor,
    ) -> Result<(), VirtualMachineError> {
        let references = self.get_reference_list();
        let hint_data_dictionary = self.get_hint_data_dictionary(&references, hint_processor)?;
        while vm.run_context.pc != address {
            vm.step(
                hint_processor,
                &mut self.exec_scopes,
                &hint_data_dictionary,
                &self.program.constants,
            )?;
        }
        Ok(())
    }

    /// Execute an exact number of steps on the program from the actual position.
    pub fn run_for_steps(
        &mut self,
        steps: usize,
        vm: &mut VirtualMachine,
        hint_processor: &dyn HintProcessor,
    ) -> Result<(), VirtualMachineError> {
        let references = self.get_reference_list();
        let hint_data_dictionary = self.get_hint_data_dictionary(&references, hint_processor)?;

        for remaining_steps in (1..=steps).rev() {
            if self.final_pc.as_ref() == Some(&vm.run_context.pc) {
                return Err(VirtualMachineError::EndOfProgram(remaining_steps));
            }

            vm.step(
                hint_processor,
                &mut self.exec_scopes,
                &hint_data_dictionary,
                &self.program.constants,
            )?;
        }

        Ok(())
    }

    /// Execute steps until a number of steps since the start of the program is reached.
    pub fn run_until_steps(
        &mut self,
        steps: usize,
        vm: &mut VirtualMachine,
        hint_processor: &dyn HintProcessor,
    ) -> Result<(), VirtualMachineError> {
        self.run_for_steps(steps.saturating_sub(vm.current_step), vm, hint_processor)
    }

    /// Mark a memory address as accesed.
    pub fn mark_as_accessed(
        &mut self,
        address: Relocatable,
        size: usize,
    ) -> Result<(), VirtualMachineError> {
        let accessed_addressess = self
            .accessed_addresses
            .as_mut()
            .ok_or(VirtualMachineError::RunNotFinished)?;

        accessed_addressess.extend((0..size).map(|i| &address + i));
        Ok(())
    }

    /// Count the number of holes present in the segments.
    pub fn get_memory_holes(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let accessed_addresses = self
            .accessed_addresses
            .as_ref()
            .ok_or(MemoryError::MissingAccessedAddresses)?;

        let mut builtin_accessed_addresses = HashSet::new();
        for (_, builtin_runner) in &vm.builtin_runners {
            builtin_accessed_addresses.extend(builtin_runner.get_memory_accesses(vm)?.into_iter());
        }

        builtin_accessed_addresses.extend(accessed_addresses.iter().cloned());
        vm.segments.get_memory_holes(&builtin_accessed_addresses)
    }

    /// Check if there are enough trace cells to fill the entire diluted checks.
    pub fn check_diluted_check_usage(
        &self,
        vm: &VirtualMachine,
    ) -> Result<(), VirtualMachineError> {
        let diluted_pool_instance = match &self.layout.diluted_pool_instance_def {
            Some(x) => x,
            None => return Ok(()),
        };

        let mut used_units_by_builtins = 0;
        for (_, builtin_runner) in &vm.builtin_runners {
            let used_units = builtin_runner.get_used_diluted_check_units(
                diluted_pool_instance.spacing,
                diluted_pool_instance.n_bits,
            );

            used_units_by_builtins += used_units
                * safe_div_usize(
                    vm.current_step,
                    builtin_runner.ratio().unwrap_or(1) as usize,
                )?;
        }

        let diluted_units = diluted_pool_instance.units_per_step as usize * vm.current_step;
        let unused_diluted_units = diluted_units - used_units_by_builtins;

        let diluted_usage_upper_bound = 1usize << diluted_pool_instance.n_bits;
        if unused_diluted_units < diluted_usage_upper_bound {
            return Err(MemoryError::InsufficientAllocatedCells.into());
        }

        Ok(())
    }

    pub fn end_run(
        &mut self,
        _disable_trace_padding: bool,
        disable_finalize_all: bool,
        vm: &mut VirtualMachine,
    ) -> Result<(), VirtualMachineError> {
        if self.run_ended {
            return Err(RunnerError::RunAlreadyFinished.into());
        }

        // Process accessed_addresses.
        self.accessed_addresses = Some({
            let accessed_addresses = vm
                .accessed_addresses
                .as_ref()
                .ok_or_else::<VirtualMachineError, _>(|| {
                    MemoryError::MissingAccessedAddresses.into()
                })?;
            let mut new_accessed_addresses = HashSet::with_capacity(accessed_addresses.len());

            for addr in accessed_addresses {
                let relocated_addr = vm.memory.relocate_value(&addr.into())?.into_owned();

                new_accessed_addresses.insert(relocated_addr.try_into().unwrap());
            }

            new_accessed_addresses
        });

        self.relocate(vm)
            .map_err(VirtualMachineError::TracerError)?;
        vm.end_run(&self.exec_scopes)?;

        if !disable_finalize_all {
            vm.segments.compute_effective_sizes(&vm.memory);
            self.run_ended = true;
        }

        Ok(())
    }

    ///Relocates the VM's memory, turning bidimensional indexes into contiguous numbers, and values into BigInts
    /// Uses the relocation_table to asign each index a number according to the value on its segment number
    fn relocate_memory(
        &mut self,
        vm: &mut VirtualMachine,
        relocation_table: &Vec<usize>,
    ) -> Result<(), MemoryError> {
        if !(self.relocated_memory.is_empty()) {
            return Err(MemoryError::Relocation);
        }
        //Relocated addresses start at 1
        self.relocated_memory.push(None);
        for (index, segment) in vm.memory.data.iter().enumerate() {
            if self.relocated_memory.len() != relocation_table[index] {
                return Err(MemoryError::Relocation);
            }

            for element in segment {
                match element {
                    Some(elem) => self
                        .relocated_memory
                        .push(Some(relocate_value(elem.clone(), relocation_table)?)),
                    None => self.relocated_memory.push(None),
                }
            }
        }
        Ok(())
    }

    ///Relocates the VM's trace, turning relocatable registers to numbered ones
    fn relocate_trace(
        &mut self,
        vm: &mut VirtualMachine,
        relocation_table: &Vec<usize>,
    ) -> Result<(), TraceError> {
        if self.relocated_trace.is_some() {
            return Err(TraceError::AlreadyRelocated);
        }

        let trace = vm.trace.as_ref().ok_or(TraceError::TraceNotEnabled)?.iter();
        let mut relocated_trace = Vec::<RelocatedTraceEntry>::with_capacity(trace.len());
        for entry in trace {
            relocated_trace.push(RelocatedTraceEntry {
                pc: relocate_trace_register(&entry.pc, relocation_table)?,
                ap: relocate_trace_register(&entry.ap, relocation_table)?,
                fp: relocate_trace_register(&entry.fp, relocation_table)?,
            })
        }
        self.relocated_trace = Some(relocated_trace);
        Ok(())
    }

    pub fn relocate(&mut self, vm: &mut VirtualMachine) -> Result<(), TraceError> {
        vm.segments.compute_effective_sizes(&vm.memory);
        // relocate_segments can fail if compute_effective_sizes is not called before.
        // The expect should be unreachable.
        let relocation_table = vm
            .segments
            .relocate_segments()
            .expect("compute_effective_sizes called but relocate_memory still returned error");
        if let Err(memory_error) = self.relocate_memory(vm, &relocation_table) {
            return Err(TraceError::MemoryError(memory_error));
        }
        if vm.trace.is_some() {
            self.relocate_trace(vm, &relocation_table)?;
        }
        Ok(())
    }

    pub fn get_builtin_segments_info(
        &self,
        vm: &VirtualMachine,
    ) -> Result<HashMap<&'static str, SegmentInfo>, RunnerError> {
        let mut builtin_segments = HashMap::new();

        for (_, builtin) in &vm.builtin_runners {
            let (name, segment_address) = builtin.get_memory_segment_addresses();
            if builtin_segments.contains_key(&name) {
                return Err(RunnerError::BuiltinSegmentNameCollision(name));
            }

            let index = segment_address.0;
            let size = segment_address.1.ok_or(RunnerError::BaseNotFinished)?;

            builtin_segments.insert(name, SegmentInfo { index, size });
        }

        Ok(builtin_segments)
    }

    pub fn get_execution_resources(
        &self,
        vm: &VirtualMachine,
    ) -> Result<ExecutionResources, TraceError> {
        let n_steps = match self.original_steps {
            Some(x) => x,
            None => vm.trace.as_ref().map(|x| x.len()).unwrap_or(0),
        };
        let n_memory_holes = self.get_memory_holes(vm)?;

        let mut builtin_instance_counter = Vec::with_capacity(vm.builtin_runners.len());
        for (key, builtin_runner) in &vm.builtin_runners {
            builtin_instance_counter
                .push((key.to_string(), builtin_runner.get_used_instances(vm)?));
        }

        Ok(ExecutionResources {
            n_steps,
            n_memory_holes,
            builtin_instance_counter,
        })
    }

    pub fn get_output(&mut self, vm: &mut VirtualMachine) -> Result<String, RunnerError> {
        let mut output = Vec::<u8>::new();
        self.write_output(vm, &mut output)?;
        let output = String::from_utf8(output).map_err(|_| RunnerError::FailedStringConversion)?;
        Ok(output)
    }

    ///Writes the values hosted in the output builtin's segment
    /// Does nothing if the output builtin is not present in the program
    pub fn write_output(
        &mut self,
        vm: &mut VirtualMachine,
        stdout: &mut dyn io::Write,
    ) -> Result<(), RunnerError> {
        //If the output builtin is present it will always be the first one
        if !vm.builtin_runners.is_empty() && vm.builtin_runners[0].0 == *"output" {
            let builtin = &vm.builtin_runners[0].1;
            vm.segments.compute_effective_sizes(&vm.memory);

            let base = builtin.base();

            // After this if block,
            // segment_used_sizes is always Some(_)
            if vm.segments.segment_used_sizes == None {
                vm.segments.compute_effective_sizes(&vm.memory);
            }

            let segment_index: usize = base
                .try_into()
                .map_err(|_| RunnerError::RunnerInTemporarySegment(base))?;
            // See previous comment, the unwrap below is safe.
            for i in 0..vm.segments.segment_used_sizes.as_ref().unwrap()[segment_index] {
                let value = vm
                    .memory
                    .get_integer(&(base, i).into())
                    .map_err(|_| RunnerError::MemoryGet((base, i).into()))?;
                writeln!(
                    stdout,
                    "{}",
                    to_field_element(value.into_owned(), vm.prime.clone())
                )
                .map_err(|_| RunnerError::WriteFail)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_from_entrypoint(
        &mut self,
        entrypoint: usize,
        args: Vec<&dyn Any>,
        typed_args: bool,
        verify_secure: bool,
        apply_modulo_to_args: bool,
        vm: &mut VirtualMachine,
        hint_processor: &dyn HintProcessor,
    ) -> Result<(), VirtualMachineError> {
        let stack = if typed_args {
            if args.len() != 1 {
                return Err(VirtualMachineError::InvalidArgCount(1, args.len()));
            }

            vm.segments.gen_typed_args(args, vm)?
        } else {
            let mut stack = Vec::new();
            for arg in args {
                let prime = match apply_modulo_to_args {
                    true => Some(&vm.prime),
                    false => None,
                };

                stack.push(vm.segments.gen_arg(arg, prime, &mut vm.memory)?);
            }

            stack
        };

        let return_fp = vm.segments.add(&mut vm.memory);
        let end = self.initialize_function_entrypoint(vm, entrypoint, stack, return_fp.into())?;
        self.initialize_vm(vm)?;

        self.run_until_pc(end, vm, hint_processor)?;
        self.end_run(true, false, vm)?;

        if verify_secure {
            verify_secure_runner(self, false, vm)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentInfo {
    pub index: isize,
    pub size: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionResources {
    pub n_steps: usize,
    pub n_memory_holes: usize,
    pub builtin_instance_counter: Vec<(String, usize)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint, bigint_str,
        hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
        relocatable,
        serde::deserialize_program::ReferenceManager,
        types::instance_definitions::bitwise_instance_def::BitwiseInstanceDef,
        utils::test_utils::*,
        vm::{trace::trace_entry::TraceEntry, vm_memory::memory::Memory},
    };
    use num_bigint::Sign;
    use std::{
        collections::{HashMap, HashSet},
        path::Path,
    };

    #[test]
    fn initialize_builtins_with_disordered_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check"), String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        assert!(cairo_runner.initialize_builtins(&mut vm).is_err());
    }

    #[test]
    fn create_cairo_runner_with_ordered_but_missing_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output"), String::from("ecdsa")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        //We only check that the creation doesnt panic
        let _cairo_runner = cairo_runner!(program);
    }

    #[test]
    fn initialize_segments_with_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        let program_base = Some(Relocatable {
            segment_index: 5,
            offset: 9,
        });
        vm.segments.num_segments = 6;
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, program_base);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: 5,
                offset: 9,
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: 6,
                offset: 0,
            })
        );
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[0].1.base(), 7);

        assert_eq!(vm.segments.num_segments, 8);
    }

    #[test]
    fn initialize_segments_no_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: 0,
                offset: 0
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: 1,
                offset: 0
            })
        );
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);

        assert_eq!(vm.segments.num_segments, 3);
    }

    #[test]
    fn initialize_state_empty_data_and_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.program_base = Some(relocatable!(1, 0));
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = Vec::new();
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_state(&mut vm, 1, stack).unwrap();
        assert_eq!(
            cairo_runner.initial_pc,
            Some(Relocatable {
                segment_index: 1,
                offset: 1
            })
        );
    }

    #[test]
    fn initialize_state_some_data_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: vec_data!((4), (6)),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory);
        }
        cairo_runner.program_base = Some(Relocatable {
            segment_index: 1,
            offset: 0,
        });
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = Vec::new();
        cairo_runner.initialize_state(&mut vm, 1, stack).unwrap();
        check_memory!(vm.memory, ((1, 0), 4), ((1, 1), 6));
    }

    #[test]
    fn initialize_state_empty_data_some_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory);
        }
        cairo_runner.program_base = Some(relocatable!(1, 0));
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = vec![mayberelocatable!(4), mayberelocatable!(6)];
        cairo_runner.initialize_state(&mut vm, 1, stack).unwrap();
        check_memory!(vm.memory, ((2, 0), 4), ((2, 1), 6));
    }

    #[test]
    fn initialize_state_no_program_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory);
        }
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: 2,
            offset: 0,
        });
        let stack = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        assert!(cairo_runner.initialize_state(&mut vm, 1, stack).is_err());
    }

    #[test]
    #[should_panic]
    fn initialize_state_no_execution_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory);
        }
        cairo_runner.program_base = Some(relocatable!(1, 0));
        let stack = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        cairo_runner.initialize_state(&mut vm, 1, stack).unwrap();
    }

    #[test]
    fn initialize_function_entrypoint_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory);
        }
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(1, 0));
        let stack = Vec::new();
        let return_fp = MaybeRelocatable::from(bigint!(9));
        cairo_runner
            .initialize_function_entrypoint(&mut vm, 0, stack, return_fp)
            .unwrap();
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(cairo_runner.initial_fp, Some(relocatable!(1, 2)));
        check_memory!(vm.memory, ((1, 0), 9), ((1, 1), (2, 0)));
    }

    #[test]
    fn initialize_function_entrypoint_some_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory);
        }
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(1, 0));
        let stack = vec![MaybeRelocatable::from(bigint!(7))];
        let return_fp = MaybeRelocatable::from(bigint!(9));
        cairo_runner
            .initialize_function_entrypoint(&mut vm, 1, stack, return_fp)
            .unwrap();
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(cairo_runner.initial_fp, Some(relocatable!(1, 3)));
        check_memory!(vm.memory, ((1, 0), 7), ((1, 1), 9), ((1, 2), (2, 0)));
    }

    #[test]
    #[should_panic]
    fn initialize_function_entrypoint_no_execution_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        let stack = vec![MaybeRelocatable::from(bigint!(7))];
        let return_fp = MaybeRelocatable::from(bigint!(9));
        cairo_runner
            .initialize_function_entrypoint(&mut vm, 1, stack, return_fp)
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn initialize_main_entrypoint_no_main() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
    }

    #[test]
    fn initialize_main_entrypoint() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: Some(1),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(0, 0));
        let return_pc = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        assert_eq!(return_pc, Relocatable::from((1, 0)));
    }

    #[test]
    fn initialize_vm_no_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: Some(1),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_vm(&mut vm).unwrap();
        assert_eq!(vm.run_context.pc, relocatable!(0, 1));
        assert_eq!(vm.run_context.ap, 2);
        assert_eq!(vm.run_context.fp, 2);
        assert_eq!(vm._program_base, Some(MaybeRelocatable::from((0, 0))));
    }

    #[test]
    fn initialize_vm_with_range_check_valid() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: Some(1),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        vm.memory = memory![((2, 0), 23), ((2, 1), 233)];
        assert_eq!(vm.builtin_runners[0].0, String::from("range_check"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);
        cairo_runner.initialize_vm(&mut vm).unwrap();
        assert!(vm
            .memory
            .validated_addresses
            .contains(&MaybeRelocatable::from((2, 0))));
        assert!(vm
            .memory
            .validated_addresses
            .contains(&MaybeRelocatable::from((2, 1))));
        assert_eq!(vm.memory.validated_addresses.len(), 2);
    }

    #[test]
    fn initialize_vm_with_range_check_invalid() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: Some(1),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        vm.memory = memory![((2, 1), 23), ((2, 4), (-1))];

        assert_eq!(
            cairo_runner.initialize_vm(&mut vm),
            Err(RunnerError::MemoryValidationError(MemoryError::FoundNonInt))
        );
    }

    //Integration tests for initialization phase

    #[test]
    /* Program used:
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
            data: vec_data!(
                (5207990763031199744_i64),
                (2),
                (2345108766317314046_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020476",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(3),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_segments(&mut vm, None);
        cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(3, 0)));

        //RunContext check
        //Registers
        assert_eq!(vm.run_context.pc, relocatable!(0, 3));
        assert_eq!(vm.run_context.ap, 2);
        assert_eq!(vm.run_context.fp, 2);
        //Memory
        check_memory!(
            vm.memory,
            ((0, 0), 5207990763031199744_i64),
            ((0, 1), 2),
            ((0, 2), 2345108766317314046_i64),
            ((0, 3), 5189976364521848832_i64),
            ((0, 4), 1),
            ((0, 5), 1226245742482522112_i64),
            (
                (0, 6),
                (
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020476",
                    10
                )
            ),
            ((0, 7), 2345108766317314046_i64),
            ((1, 0), (2, 0)),
            ((1, 1), (3, 0))
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
            data: vec_data!(
                (4612671182993129469_i64),
                (5198983563776393216_i64),
                (1),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(4),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(4, 0)));

        //RunContext check
        //Registers
        assert_eq!(vm.run_context.pc, relocatable!(0, 4));
        assert_eq!(vm.run_context.ap, 3);
        assert_eq!(vm.run_context.fp, 3);
        //Memory
        check_memory!(
            vm.memory,
            ((0, 0), 4612671182993129469_i64),
            ((0, 1), 5198983563776393216_i64),
            ((0, 2), 1),
            ((0, 3), 2345108766317314046_i64),
            ((0, 4), 5191102247248822272_i64),
            ((0, 5), 5189976364521848832_i64),
            ((0, 6), 1),
            ((0, 7), 1226245742482522112_i64),
            (
                (0, 8),
                (
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )
            ),
            ((0, 9), 2345108766317314046_i64),
            ((1, 0), (2, 0)),
            ((1, 1), (3, 0)),
            ((1, 2), (4, 0))
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
            data: vec_data!(
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(8),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(4, 0)));

        //RunContext check
        //Registers
        assert_eq!(vm.run_context.pc, relocatable!(0, 8));
        assert_eq!(vm.run_context.ap, 3);
        assert_eq!(vm.run_context.fp, 3);
        //Memory
        check_memory!(
            vm.memory,
            ((0, 0), 4612671182993129469_i64),
            ((0, 1), 5189976364521848832_i64),
            ((0, 2), 18446744073709551615_i128),
            ((0, 3), 5199546496550207487_i64),
            ((0, 4), 4612389712311386111_i64),
            ((0, 5), 5198983563776393216_i64),
            ((0, 6), 2),
            ((0, 7), 2345108766317314046_i64),
            ((0, 8), 5191102247248822272_i64),
            ((0, 9), 5189976364521848832_i64),
            ((0, 10), 7),
            ((0, 11), 1226245742482522112_i64),
            (
                (0, 12),
                (
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )
            ),
            ((0, 13), 2345108766317314046_i64),
            ((1, 0), (2, 0)),
            ((1, 1), (3, 0)),
            ((1, 2), (4, 0))
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
            data: vec_data!(
                (5207990763031199744_i64),
                (2),
                (2345108766317314046_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020476",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(3),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        assert_eq!(end, Relocatable::from((3, 0)));
        cairo_runner.initialize_vm(&mut vm).unwrap();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(vm.run_context.pc, Relocatable::from((3, 0)));

        assert_eq!(vm.run_context.ap, 6);

        assert_eq!(vm.run_context.fp, 0);

        //Check each TraceEntry in trace
        let trace = vm.trace.unwrap();
        assert_eq!(trace.len(), 5);
        trace_check!(
            trace,
            [
                ((0, 3), (1, 2), (1, 2)),
                ((0, 5), (1, 3), (1, 2)),
                ((0, 0), (1, 5), (1, 5)),
                ((0, 2), (1, 6), (1, 5)),
                ((0, 7), (1, 6), (1, 2))
            ]
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
    fn initialize_and_run_range_check_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(8),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(vm.run_context.pc, Relocatable::from((4, 0)));

        assert_eq!(vm.run_context.ap, 10);

        assert_eq!(vm.run_context.fp, 0);

        //Check each TraceEntry in trace
        let trace = vm.trace.unwrap();
        assert_eq!(trace.len(), 10);
        trace_check!(
            trace,
            [
                ((0, 8), (1, 3), (1, 3)),
                ((0, 9), (1, 4), (1, 3)),
                ((0, 11), (1, 5), (1, 3)),
                ((0, 0), (1, 7), (1, 7)),
                ((0, 1), (1, 7), (1, 7)),
                ((0, 3), (1, 8), (1, 7)),
                ((0, 4), (1, 9), (1, 7)),
                ((0, 5), (1, 9), (1, 7)),
                ((0, 7), (1, 10), (1, 7)),
                ((0, 13), (1, 10), (1, 3))
            ]
        );
        //Check the range_check builtin segment
        assert_eq!(vm.builtin_runners[0].0, String::from("range_check"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);

        check_memory!(vm.memory, ((2, 0), 7), ((2, 1), 18446744073709551608_i128));
        assert_eq!(vm.memory.get(&MaybeRelocatable::from((2, 2))), Ok(None));
    }

    #[test]
    /*Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        let b = 17 * a
        serialize_word(b)
        return()
    end

    main = 4
    data = [
    4612671182993129469,
    5198983563776393216,
    1,
    2345108766317314046,
    5191102247248822272,
    5189976364521848832,
    1,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020474,
    5189976364521848832,
    17,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020470,
    2345108766317314046
    ]
    */
    fn initialize_and_run_output_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5198983563776393216_i64),
                (1),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )),
                (5189976364521848832_i64),
                (17),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(4),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        //todo
        assert_eq!(vm.run_context.pc, Relocatable::from((4, 0)));

        assert_eq!(vm.run_context.ap, 12);

        assert_eq!(vm.run_context.fp, 0);

        //Check each TraceEntry in trace
        let trace = vm.trace.unwrap();
        assert_eq!(trace.len(), 12);
        trace_check!(
            trace,
            [
                ((0, 4), (1, 3), (1, 3)),
                ((0, 5), (1, 4), (1, 3)),
                ((0, 7), (1, 5), (1, 3)),
                ((0, 0), (1, 7), (1, 7)),
                ((0, 1), (1, 7), (1, 7)),
                ((0, 3), (1, 8), (1, 7)),
                ((0, 9), (1, 8), (1, 3)),
                ((0, 11), (1, 9), (1, 3)),
                ((0, 0), (1, 11), (1, 11)),
                ((0, 1), (1, 11), (1, 11)),
                ((0, 3), (1, 12), (1, 11)),
                ((0, 13), (1, 12), (1, 3))
            ]
        );
        //Check that the output to be printed is correct
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);
        check_memory!(vm.memory, ((2, 0), 1), ((2, 1), 17));
        assert_eq!(vm.memory.get(&MaybeRelocatable::from((2, 2))), Ok(None));
    }

    #[test]
    /*Program used:
    %builtins output range_check

    from starkware.cairo.common.serialize import serialize_word

    func check_range{range_check_ptr}(num) -> (num : felt):

        # Check that 0 <= num < 2**64.
        [range_check_ptr] = num
        assert [range_check_ptr + 1] = 2 ** 64 - 1 - num
        let range_check_ptr = range_check_ptr + 2
        return(num)
    end

    func main{output_ptr: felt*, range_check_ptr: felt}():
        let num: felt = check_range(7)
        serialize_word(num)
        return()
    end

    main = 13
    data = [
    4612671182993129469,
    5198983563776393216,
    1,
    2345108766317314046,
    4612671182993129469,
    5189976364521848832,
    18446744073709551615,
    5199546496550207487,
    4612389712311386111,
    5198983563776393216,
    2,
    5191102247248822272,
    2345108766317314046,
    5191102247248822272,
    5189976364521848832,
    7,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020469,
    5191102242953854976,
    5193354051357474816,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020461,
    5193354029882638336,
    2345108766317314046]
    */
    fn initialize_and_run_output_range_check_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("output"), String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5198983563776393216_i64),
                (1),
                (2345108766317314046_i64),
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (5191102247248822272_i64),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020469",
                    10
                )),
                (5191102242953854976_i64),
                (5193354051357474816_i64),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020461",
                    10
                )),
                (5193354029882638336_i64),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(13),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(vm.run_context.pc, Relocatable::from((5, 0)));

        assert_eq!(vm.run_context.ap, 18);

        assert_eq!(vm.run_context.fp, 0);

        //Check each TraceEntry in trace
        let trace = vm.trace.unwrap();
        assert_eq!(trace.len(), 18);
        trace_check!(
            trace,
            [
                ((0, 13), (1, 4), (1, 4)),
                ((0, 14), (1, 5), (1, 4)),
                ((0, 16), (1, 6), (1, 4)),
                ((0, 4), (1, 8), (1, 8)),
                ((0, 5), (1, 8), (1, 8)),
                ((0, 7), (1, 9), (1, 8)),
                ((0, 8), (1, 10), (1, 8)),
                ((0, 9), (1, 10), (1, 8)),
                ((0, 11), (1, 11), (1, 8)),
                ((0, 12), (1, 12), (1, 8)),
                ((0, 18), (1, 12), (1, 4)),
                ((0, 19), (1, 13), (1, 4)),
                ((0, 20), (1, 14), (1, 4)),
                ((0, 0), (1, 16), (1, 16)),
                ((0, 1), (1, 16), (1, 16)),
                ((0, 3), (1, 17), (1, 16)),
                ((0, 22), (1, 17), (1, 4)),
                ((0, 23), (1, 18), (1, 4))
            ]
        );
        //Check the range_check builtin segment
        assert_eq!(vm.builtin_runners[1].0, String::from("range_check"));
        assert_eq!(vm.builtin_runners[1].1.base(), 3);

        check_memory!(vm.memory, ((3, 0), 7), ((3, 1), 18446744073709551608_i128));
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 2))).unwrap(),
            None
        );

        //Check the output segment
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);

        check_memory!(vm.memory, ((2, 0), 7));
        assert_eq!(
            vm.memory.get(&(MaybeRelocatable::from((2, 1)))).unwrap(),
            None
        );
    }

    #[test]
    /*Memory from this test is taken from a cairo program execution
    Program used:
        func main():
        let a = 1
        [ap + 3] = 5
        return()

    end
    Final Memory:
    {RelocatableValue(segment_index=0, offset=0): 4613515612218425347,
     RelocatableValue(segment_index=0, offset=1): 5,
     RelocatableValue(segment_index=0, offset=2): 2345108766317314046,
     RelocatableValue(segment_index=1, offset=0): RelocatableValue(segment_index=2, offset=0),
     RelocatableValue(segment_index=1, offset=1): RelocatableValue(segment_index=3, offset=0),
     RelocatableValue(segment_index=1, offset=5): 5}
    Relocated Memory:
        1     4613515612218425347
        2     5
        3     2345108766317314046
        4     10
        5     10
        ⋮
        9     5
    */
    fn relocate_memory_with_gap() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        for _ in 0..4 {
            vm.segments.add(&mut vm.memory);
        }
        // Memory initialization without macro
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(4613515612218425347_i64)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(2345108766317314046_i64)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((3, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        vm.segments.compute_effective_sizes(&vm.memory);
        let rel_table = vm
            .segments
            .relocate_segments()
            .expect("Couldn't relocate after compute effective sizes");
        assert_eq!(cairo_runner.relocate_memory(&mut vm, &rel_table), Ok(()));
        assert_eq!(cairo_runner.relocated_memory[0], None);
        assert_eq!(
            cairo_runner.relocated_memory[1],
            Some(bigint!(4613515612218425347_i64))
        );
        assert_eq!(cairo_runner.relocated_memory[2], Some(bigint!(5)));
        assert_eq!(
            cairo_runner.relocated_memory[3],
            Some(bigint!(2345108766317314046_i64))
        );
        assert_eq!(cairo_runner.relocated_memory[4], Some(bigint!(10)));
        assert_eq!(cairo_runner.relocated_memory[5], Some(bigint!(10)));
        assert_eq!(cairo_runner.relocated_memory[6], None);
        assert_eq!(cairo_runner.relocated_memory[7], None);
        assert_eq!(cairo_runner.relocated_memory[8], None);
        assert_eq!(cairo_runner.relocated_memory[9], Some(bigint!(5)));
    }

    #[test]
    /* Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        let b = 17 * a
        serialize_word(b)
        return()
    end
    Relocated Memory:
        1     4612671182993129469
        2     5198983563776393216
        3     1
        4     2345108766317314046
        5     5191102247248822272
        6     5189976364521848832
        7     1
        8     1226245742482522112
        9     -7
        10    5189976364521848832
        11    17
        12    1226245742482522112
        13    -11
        14    2345108766317314046
        15    27
        16    29
        17    29
        18    27
        19    1
        20    18
        21    10
        22    28
        23    17
        24    18
        25    14
        26    29
        27    1
        28    17
     */
    fn initialize_run_and_relocate_output_builtin() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5198983563776393216_i64),
                (1),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )),
                (5189976364521848832_i64),
                (17),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(4),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        vm.segments.compute_effective_sizes(&vm.memory);
        let rel_table = vm
            .segments
            .relocate_segments()
            .expect("Couldn't relocate after compute effective sizes");
        assert_eq!(cairo_runner.relocate_memory(&mut vm, &rel_table), Ok(()));
        assert_eq!(cairo_runner.relocated_memory[0], None);
        assert_eq!(
            cairo_runner.relocated_memory[1],
            Some(bigint!(4612671182993129469_i64))
        );
        assert_eq!(
            cairo_runner.relocated_memory[2],
            Some(bigint!(5198983563776393216_i64))
        );
        assert_eq!(cairo_runner.relocated_memory[3], Some(bigint!(1)));
        assert_eq!(
            cairo_runner.relocated_memory[4],
            Some(bigint!(2345108766317314046_i64))
        );
        assert_eq!(
            cairo_runner.relocated_memory[5],
            Some(bigint!(5191102247248822272_i64))
        );
        assert_eq!(
            cairo_runner.relocated_memory[6],
            Some(bigint!(5189976364521848832_i64))
        );
        assert_eq!(cairo_runner.relocated_memory[7], Some(bigint!(1)));
        assert_eq!(
            cairo_runner.relocated_memory[8],
            Some(bigint!(1226245742482522112_i64))
        );
        assert_eq!(
            cairo_runner.relocated_memory[9],
            Some(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020474"
            ))
        );
        assert_eq!(
            cairo_runner.relocated_memory[10],
            Some(bigint!(5189976364521848832_i64))
        );
        assert_eq!(cairo_runner.relocated_memory[11], Some(bigint!(17)));
        assert_eq!(
            cairo_runner.relocated_memory[12],
            Some(bigint!(1226245742482522112_i64))
        );
        assert_eq!(
            cairo_runner.relocated_memory[13],
            Some(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020470"
            ))
        );
        assert_eq!(
            cairo_runner.relocated_memory[14],
            Some(bigint!(2345108766317314046_i64))
        );
        assert_eq!(cairo_runner.relocated_memory[15], Some(bigint!(27)));
        assert_eq!(cairo_runner.relocated_memory[16], Some(bigint!(29)));
        assert_eq!(cairo_runner.relocated_memory[17], Some(bigint!(29)));
        assert_eq!(cairo_runner.relocated_memory[18], Some(bigint!(27)));
        assert_eq!(cairo_runner.relocated_memory[19], Some(bigint!(1)));
        assert_eq!(cairo_runner.relocated_memory[20], Some(bigint!(18)));
        assert_eq!(cairo_runner.relocated_memory[21], Some(bigint!(10)));
        assert_eq!(cairo_runner.relocated_memory[22], Some(bigint!(28)));
        assert_eq!(cairo_runner.relocated_memory[23], Some(bigint!(17)));
        assert_eq!(cairo_runner.relocated_memory[24], Some(bigint!(18)));
        assert_eq!(cairo_runner.relocated_memory[25], Some(bigint!(14)));
        assert_eq!(cairo_runner.relocated_memory[26], Some(bigint!(29)));
        assert_eq!(cairo_runner.relocated_memory[27], Some(bigint!(1)));
        assert_eq!(cairo_runner.relocated_memory[28], Some(bigint!(17)));
    }

    #[test]
    /* Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        let b = 17 * a
        serialize_word(b)
        return()
    end

    Relocated Trace:
    [TraceEntry(pc=5, ap=18, fp=18),
     TraceEntry(pc=6, ap=19, fp=18),
     TraceEntry(pc=8, ap=20, fp=18),
     TraceEntry(pc=1, ap=22, fp=22),
     TraceEntry(pc=2, ap=22, fp=22),
     TraceEntry(pc=4, ap=23, fp=22),
     TraceEntry(pc=10, ap=23, fp=18),
    */
    fn relocate_trace_output_builtin() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5198983563776393216_i64),
                (1),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )),
                (5189976364521848832_i64),
                (17),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(4),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        vm.segments.compute_effective_sizes(&vm.memory);
        let rel_table = vm
            .segments
            .relocate_segments()
            .expect("Couldn't relocate after compute effective sizes");
        cairo_runner.relocate_trace(&mut vm, &rel_table).unwrap();
        let relocated_trace = cairo_runner.relocated_trace.unwrap();
        assert_eq!(relocated_trace.len(), 12);
        assert_eq!(
            relocated_trace[0],
            RelocatedTraceEntry {
                pc: 5,
                ap: 18,
                fp: 18
            }
        );
        assert_eq!(
            relocated_trace[1],
            RelocatedTraceEntry {
                pc: 6,
                ap: 19,
                fp: 18
            }
        );
        assert_eq!(
            relocated_trace[2],
            RelocatedTraceEntry {
                pc: 8,
                ap: 20,
                fp: 18
            }
        );
        assert_eq!(
            relocated_trace[3],
            RelocatedTraceEntry {
                pc: 1,
                ap: 22,
                fp: 22
            }
        );
        assert_eq!(
            relocated_trace[4],
            RelocatedTraceEntry {
                pc: 2,
                ap: 22,
                fp: 22
            }
        );
        assert_eq!(
            relocated_trace[5],
            RelocatedTraceEntry {
                pc: 4,
                ap: 23,
                fp: 22
            }
        );
        assert_eq!(
            relocated_trace[6],
            RelocatedTraceEntry {
                pc: 10,
                ap: 23,
                fp: 18
            }
        );
        assert_eq!(
            relocated_trace[7],
            RelocatedTraceEntry {
                pc: 12,
                ap: 24,
                fp: 18
            }
        );
        assert_eq!(
            relocated_trace[8],
            RelocatedTraceEntry {
                pc: 1,
                ap: 26,
                fp: 26
            }
        );
        assert_eq!(
            relocated_trace[9],
            RelocatedTraceEntry {
                pc: 2,
                ap: 26,
                fp: 26
            }
        );
        assert_eq!(
            relocated_trace[10],
            RelocatedTraceEntry {
                pc: 4,
                ap: 27,
                fp: 26
            }
        );
        assert_eq!(
            relocated_trace[11],
            RelocatedTraceEntry {
                pc: 14,
                ap: 27,
                fp: 18
            }
        );
    }

    #[test]
    fn write_output_from_preset_memory() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);

        vm.memory = memory![((2, 0), 1), ((2, 1), 2)];
        vm.segments.segment_used_sizes = Some(vec![0, 0, 2]);
        let mut stdout = Vec::<u8>::new();
        cairo_runner.write_output(&mut vm, &mut stdout).unwrap();
        assert_eq!(String::from_utf8(stdout), Ok(String::from("1\n2\n")));
    }

    #[test]
    /*Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        return()
    end */
    fn write_output_from_program() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5198983563776393216_i64),
                (1),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (1),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474",
                    10
                )),
                (5189976364521848832_i64),
                (17),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(4),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        let end = cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();
        //Execution Phase
        let hint_processor = BuiltinHintProcessor::new_empty();
        assert_eq!(
            cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
            Ok(())
        );
        let mut stdout = Vec::<u8>::new();
        cairo_runner.write_output(&mut vm, &mut stdout).unwrap();
        assert_eq!(String::from_utf8(stdout), Ok(String::from("1\n17\n")));
    }

    #[test]
    fn write_output_from_preset_memory_neg_output() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[0].1.base(), 2);
        vm.memory = memory![(
            (2, 0),
            (
                b"3270867057177188607814717243084834301278723532952411121381966378910183338911",
                10
            )
        )];
        vm.segments.segment_used_sizes = Some(vec![0, 0, 1]);
        let mut stdout = Vec::<u8>::new();
        cairo_runner.write_output(&mut vm, &mut stdout).unwrap();
        assert_eq!(
            String::from_utf8(stdout),
            Ok(String::from(
                "-347635731488942605882605540010235804344383682379185578591125677225688681570\n"
            ))
        );
    }

    #[test]
    fn insert_all_builtins_in_order() {
        let program = Program {
            builtins: vec![
                String::from("output"),
                String::from("pedersen"),
                String::from("range_check"),
                String::from("bitwise"),
                String::from("ec_op"),
            ],
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        assert_eq!(vm.builtin_runners[0].0, String::from("output"));
        assert_eq!(vm.builtin_runners[1].0, String::from("pedersen"));
        assert_eq!(vm.builtin_runners[2].0, String::from("range_check"));
        assert_eq!(vm.builtin_runners[3].0, String::from("bitwise"));
        assert_eq!(vm.builtin_runners[4].0, String::from("ec_op"));
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
    fn run_for_steps() {
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            main: Some(8),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
            constants: HashMap::new(),
        };

        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(&program);

        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);

        cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();

        // Full takes 10 steps.
        assert_eq!(
            cairo_runner.run_for_steps(8, &mut vm, &hint_processor),
            Ok(())
        );
        assert_eq!(
            cairo_runner.run_for_steps(8, &mut vm, &hint_processor),
            Err(VirtualMachineError::EndOfProgram(8 - 2))
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
    fn run_until_steps() {
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec_data!(
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(8),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(&program);

        let mut vm = vm!(true);
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);

        cairo_runner.initialize_main_entrypoint(&mut vm).unwrap();
        cairo_runner.initialize_vm(&mut vm).unwrap();

        // Full takes 10 steps.
        assert_eq!(
            cairo_runner.run_until_steps(8, &mut vm, &hint_processor),
            Ok(())
        );
        assert_eq!(
            cairo_runner.run_until_steps(10, &mut vm, &hint_processor),
            Ok(())
        );
        assert_eq!(
            cairo_runner.run_until_steps(11, &mut vm, &hint_processor),
            Err(VirtualMachineError::EndOfProgram(1)),
        );
    }

    #[test]
    fn get_constants() {
        let program_constants = HashMap::from([
            ("MAX".to_string(), bigint!(300)),
            ("MIN".to_string(), bigint!(20)),
        ]);
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: program_constants.clone(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };
        let cairo_runner = cairo_runner!(program);
        assert_eq!(cairo_runner.get_constants(), &program_constants);
    }

    #[test]
    fn mark_as_accessed() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);

        assert_eq!(
            cairo_runner.mark_as_accessed((0, 0).into(), 3),
            Err(VirtualMachineError::RunNotFinished),
        );
    }

    #[test]
    fn mark_as_accessed_missing_accessed_addresses() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);

        cairo_runner.accessed_addresses = Some(HashSet::new());
        cairo_runner.mark_as_accessed((0, 0).into(), 3).unwrap();
        cairo_runner.mark_as_accessed((0, 10).into(), 2).unwrap();
        cairo_runner.mark_as_accessed((1, 1).into(), 1).unwrap();
        assert_eq!(
            cairo_runner.accessed_addresses.unwrap(),
            [
                (0, 0).into(),
                (0, 1).into(),
                (0, 2).into(),
                (0, 10).into(),
                (0, 11).into(),
                (1, 1).into(),
            ]
            .into_iter()
            .collect(),
        );
    }

    #[test]
    fn get_memory_holes_missing_accessed_addresses() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let cairo_runner = cairo_runner!(program);
        let vm = vm!();

        assert_eq!(
            cairo_runner.get_memory_holes(&vm),
            Err(MemoryError::MissingAccessedAddresses),
        );
    }

    #[test]
    fn get_memory_holes_missing_segment_used_sizes() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.accessed_addresses = Some(HashSet::new());
        vm.builtin_runners = Vec::new();
        assert_eq!(
            cairo_runner.get_memory_holes(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_holes_empty() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.accessed_addresses = Some(HashSet::new());
        vm.builtin_runners = Vec::new();
        vm.segments.segment_used_sizes = Some(Vec::new());
        assert_eq!(cairo_runner.get_memory_holes(&vm), Ok(0));
    }

    #[test]
    fn get_memory_holes_empty_builtins() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.accessed_addresses =
            Some([(0, 0).into(), (0, 2).into()].into_iter().collect());
        vm.builtin_runners = Vec::new();
        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(cairo_runner.get_memory_holes(&vm), Ok(2));
    }

    #[test]
    fn get_memory_holes_empty_accesses() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.accessed_addresses = Some(HashSet::new());
        vm.builtin_runners = vec![{
            let mut builtin_runner: BuiltinRunner = OutputBuiltinRunner::new().into();
            builtin_runner.initialize_segments(&mut vm.segments, &mut vm.memory);

            ("output".to_string(), builtin_runner)
        }];
        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(cairo_runner.get_memory_holes(&vm), Ok(0));
    }

    #[test]
    fn get_memory_holes() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.accessed_addresses =
            Some([(1, 0).into(), (1, 2).into()].into_iter().collect());
        vm.builtin_runners = vec![{
            let mut builtin_runner: BuiltinRunner = OutputBuiltinRunner::new().into();
            builtin_runner.initialize_segments(&mut vm.segments, &mut vm.memory);

            ("output".to_string(), builtin_runner)
        }];
        vm.segments.segment_used_sizes = Some(vec![4, 4]);
        assert_eq!(cairo_runner.get_memory_holes(&vm), Ok(2));
    }

    /// Test that check_diluted_check_usage() works without a diluted pool
    /// instance.
    #[test]
    fn check_diluted_check_usage_without_pool_instance() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let vm = vm!();

        cairo_runner.layout.diluted_pool_instance_def = None;
        assert_eq!(cairo_runner.check_diluted_check_usage(&vm), Ok(()));
    }

    /// Test that check_diluted_check_usage() works without builtin runners.
    #[test]
    fn check_diluted_check_usage_without_builtin_runners() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        vm.current_step = 10000;
        vm.builtin_runners = vec![];
        assert_eq!(cairo_runner.check_diluted_check_usage(&vm), Ok(()));
    }

    /// Test that check_diluted_check_usage() fails when there aren't enough
    /// allocated units.
    #[test]
    fn check_diluted_check_usage_insufficient_allocated_cells() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        vm.current_step = 100;
        vm.builtin_runners = vec![];
        assert_eq!(
            cairo_runner.check_diluted_check_usage(&vm),
            Err(MemoryError::InsufficientAllocatedCells.into()),
        );
    }

    /// Test that check_diluted_check_usage() succeeds when all the conditions
    /// are met.
    #[test]
    fn check_diluted_check_usage() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        vm.current_step = 8192;
        vm.builtin_runners = vec![(
            "bitwise".to_string(),
            BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default()).into(),
        )];
        assert_eq!(cairo_runner.check_diluted_check_usage(&vm), Ok(()),);
    }

    #[test]
    fn end_run_missing_accessed_addresses() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        assert_eq!(
            cairo_runner.end_run(true, false, &mut vm),
            Err(MemoryError::MissingAccessedAddresses.into()),
        );
    }

    #[test]
    fn end_run_run_already_finished() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.run_ended = true;
        assert_eq!(
            cairo_runner.end_run(true, false, &mut vm),
            Err(RunnerError::RunAlreadyFinished.into()),
        );
    }

    #[test]
    fn end_run() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        vm.accessed_addresses = Some(Vec::new());
        assert_eq!(cairo_runner.end_run(true, false, &mut vm), Ok(()));

        cairo_runner.run_ended = false;
        cairo_runner.relocated_memory.clear();
        assert_eq!(cairo_runner.end_run(true, true, &mut vm), Ok(()));
        assert!(!cairo_runner.run_ended);
    }

    #[test]
    fn get_builtin_segments_info_empty() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let cairo_runner = CairoRunner::new(&program, "all").unwrap();
        let vm = vm!();

        assert_eq!(
            cairo_runner.get_builtin_segments_info(&vm),
            Ok(HashMap::new()),
        );
    }

    #[test]
    fn get_builtin_segments_info_base_not_finished() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let cairo_runner = CairoRunner::new(&program, "all").unwrap();
        let mut vm = vm!();

        vm.builtin_runners = vec![(
            "output".to_string(),
            BuiltinRunner::Output(OutputBuiltinRunner::new()),
        )];
        assert_eq!(
            cairo_runner.get_builtin_segments_info(&vm),
            Err(RunnerError::BaseNotFinished),
        );
    }

    #[test]
    fn get_execution_resources_trace_not_enabled() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.accessed_addresses = Some(HashSet::new());
        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(
            cairo_runner.get_execution_resources(&vm),
            Ok(ExecutionResources {
                n_steps: 0,
                n_memory_holes: 0,
                builtin_instance_counter: Vec::new(),
            }),
        );
    }

    #[test]
    fn get_execution_resources_empty_builtins() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.original_steps = Some(10);
        cairo_runner.accessed_addresses = Some(HashSet::new());
        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(
            cairo_runner.get_execution_resources(&vm),
            Ok(ExecutionResources {
                n_steps: 10,
                n_memory_holes: 0,
                builtin_instance_counter: Vec::new(),
            }),
        );
    }

    #[test]
    fn get_execution_resources() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();

        cairo_runner.original_steps = Some(10);
        cairo_runner.accessed_addresses = Some(HashSet::new());
        vm.segments.segment_used_sizes = Some(vec![4]);
        vm.builtin_runners = vec![{
            let mut builtin = OutputBuiltinRunner::new();
            builtin.initialize_segments(&mut vm.segments, &mut vm.memory);

            ("output".to_string(), BuiltinRunner::Output(builtin))
        }];
        assert_eq!(
            cairo_runner.get_execution_resources(&vm),
            Ok(ExecutionResources {
                n_steps: 10,
                n_memory_holes: 0,
                builtin_instance_counter: vec![("output".to_string(), 4)],
            }),
        );
    }

    /// Test that the call to .run_from_entrypoint() with args.count() != 1 when
    /// typed_args is true fails.
    #[test]
    fn run_from_entrypoint_typed_args_invalid_arg_count() {
        let program =
            Program::from_file(Path::new("cairo_programs/not_main.json"), "main").unwrap();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        let hint_processor = BuiltinHintProcessor::new_empty();

        let entrypoint = program
            .identifiers
            .get("__main__.not_main")
            .unwrap()
            .pc
            .unwrap();
        assert_eq!(
            cairo_runner.run_from_entrypoint(
                entrypoint,
                vec![],
                true,
                true,
                true,
                &mut vm,
                &hint_processor,
            ),
            Err(VirtualMachineError::InvalidArgCount(1, 0)),
        );
        assert_eq!(
            cairo_runner.run_from_entrypoint(
                entrypoint,
                vec![&mayberelocatable!(0), &mayberelocatable!(1)],
                true,
                true,
                true,
                &mut vm,
                &hint_processor,
            ),
            Err(VirtualMachineError::InvalidArgCount(1, 2)),
        );
    }

    /// Test that the call to .run_from_entrypoint() with args.count() == 1 when
    /// typed_args is true succeeds.
    #[test]
    fn run_from_entrypoint_typed_args() {
        let program =
            Program::from_file(Path::new("cairo_programs/not_main.json"), "main").unwrap();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        let hint_processor = BuiltinHintProcessor::new_empty();

        let entrypoint = program
            .identifiers
            .get("__main__.not_main")
            .unwrap()
            .pc
            .unwrap();

        vm.accessed_addresses = Some(Vec::new());
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        assert_eq!(
            cairo_runner.run_from_entrypoint(
                entrypoint,
                vec![&mayberelocatable!(0)],
                true,
                true,
                true,
                &mut vm,
                &hint_processor,
            ),
            Ok(()),
        );
    }

    /// Test that the call to .run_from_entrypoint() when typed_args is false
    /// succeeds.
    #[test]
    fn run_from_entrypoint_untyped_args() {
        let program =
            Program::from_file(Path::new("cairo_programs/not_main.json"), "main").unwrap();
        let mut cairo_runner = cairo_runner!(program);
        let mut vm = vm!();
        let hint_processor = BuiltinHintProcessor::new_empty();

        let entrypoint = program
            .identifiers
            .get("__main__.not_main")
            .unwrap()
            .pc
            .unwrap();

        vm.accessed_addresses = Some(Vec::new());
        cairo_runner.initialize_builtins(&mut vm).unwrap();
        cairo_runner.initialize_segments(&mut vm, None);
        assert_eq!(
            cairo_runner.run_from_entrypoint(
                entrypoint,
                vec![],
                false,
                true,
                true,
                &mut vm,
                &hint_processor,
            ),
            Ok(()),
        );
    }
}

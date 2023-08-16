#![allow(unused_imports)]
use bincode::enc::write::Writer;
use cairo_lang_compiler::{compile_cairo_project_at_path, CompilerConfig};
use cairo_lang_runner::{
    build_hints_dict, casm_run::RunFunctionContext, token_gas_cost, CairoHintProcessor,
    SierraCasmRunner, StarknetState,
};
use cairo_lang_sierra::{extensions::gas::CostTokenType, ProgramParser};
use cairo_lang_sierra_to_casm::{compiler::compile, metadata::calc_metadata};
use cairo_lang_utils::ordered_hash_map::OrderedHashMap;
use cairo_vm::cairo_run;
use cairo_vm::{
    felt::Felt252,
    serde::deserialize_program::ReferenceManager,
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{
        runners::cairo_runner::{CairoRunner, RunResources},
        vm_core::VirtualMachine,
    },
};
use itertools::chain;
use std::io::BufWriter;
use std::io::Write;
use std::{collections::HashMap, io, path::Path};

pub struct FileWriter {
    buf_writer: io::BufWriter<std::fs::File>,
    bytes_written: usize,
}

impl bincode::enc::write::Writer for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        self.buf_writer
            .write_all(bytes)
            .map_err(|e| bincode::error::EncodeError::Io {
                inner: e,
                index: self.bytes_written,
            })?;

        self.bytes_written += bytes.len();

        Ok(())
    }
}

impl FileWriter {
    fn new(buf_writer: io::BufWriter<std::fs::File>) -> Self {
        Self {
            buf_writer,
            bytes_written: 0,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buf_writer.flush()
    }
}

fn main() {
    // The sierra program can be read directly from a file:
    // let sierra_code = std::fs::read_to_string("fibonacci.sierra").unwrap();
    // let sierra_program = ProgramParser::new().parse(&sierra_code).unwrap();

    // Or it can be compiled from a Cairo 1 program:
    let compiler_config = CompilerConfig {
        replace_ids: true,
        ..CompilerConfig::default()
    };
    let sierra_program =
        (*compile_cairo_project_at_path(Path::new("fibonacci.cairo"), compiler_config).unwrap())
            .clone();

    // Just a dummy variable needed for the SierraCasmRunner. Doesn't seem to be
    // important for running Cairo 1 programs.
    let contracts_info = OrderedHashMap::default();

    // We need this runner to use the `find_function` method for main().
    let casm_runner = SierraCasmRunner::new(
        sierra_program.clone(),
        Some(Default::default()),
        contracts_info,
    )
    .unwrap();

    let main_func = casm_runner.find_function("::main").unwrap();
    let initial_gas = 9999999999999_usize;

    // Entry code and footer are part of the whole instructions that are
    // ran by the VM.
    let (entry_code, builtins) = casm_runner
        .create_entry_code(main_func, &[], initial_gas)
        .unwrap();
    let footer = casm_runner.create_code_footer();

    let check_gas_usage = true;
    let metadata = calc_metadata(&sierra_program, Default::default()).unwrap();
    let casm_program = compile(&sierra_program, &metadata, check_gas_usage).unwrap();

    let instructions = chain!(
        entry_code.iter(),
        casm_program.instructions.iter(),
        footer.iter()
    );

    let (hints_dict, string_to_hint) = build_hints_dict(instructions.clone());

    let data: Vec<MaybeRelocatable> = instructions
        .flat_map(|inst| inst.assemble().encode())
        .map(Felt252::from)
        .map(MaybeRelocatable::from)
        .collect();

    // Uncomment for printing bytecode
    // print_bytecode(&data);

    let data_len = data.len();

    let program = Program::new(
        builtins,
        data,
        Some(0),
        hints_dict,
        ReferenceManager {
            references: Vec::new(),
        },
        HashMap::new(),
        vec![],
        None,
    )
    .unwrap();

    let mut runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
    let mut vm = VirtualMachine::new(true);
    let end = runner.initialize(&mut vm).unwrap();

    let function_context = RunFunctionContext {
        vm: &mut vm,
        data_len,
    };

    additional_initialization(function_context);

    let mut hint_processor = CairoHintProcessor {
        runner: None,
        string_to_hint,
        starknet_state: StarknetState::default(),
        run_resources: RunResources::default(),
    };

    runner
        .run_until_pc(end, &mut vm, &mut hint_processor)
        .unwrap();
    runner
        .end_run(true, false, &mut vm, &mut hint_processor)
        .unwrap();

    runner.relocate(&mut vm, true).unwrap();

    let relocated_trace = vm.get_relocated_trace().unwrap();

    let trace_path = "test.trace";
    let trace_file = std::fs::File::create(trace_path).unwrap();
    let mut trace_writer =
        FileWriter::new(io::BufWriter::with_capacity(3 * 1024 * 1024, trace_file));

    cairo_run::write_encoded_trace(relocated_trace, &mut trace_writer).unwrap();
    trace_writer.flush().unwrap();

    let memory_path = "test.memory";
    let memory_file = std::fs::File::create(memory_path).unwrap();
    let mut memory_writer =
        FileWriter::new(io::BufWriter::with_capacity(5 * 1024 * 1024, memory_file));

    cairo_run::write_encoded_memory(&runner.relocated_memory, &mut memory_writer).unwrap();
    memory_writer.flush().unwrap();
    println!();
    println!("Cairo1 program ran successfully");
}

fn additional_initialization(context: RunFunctionContext) {
    let vm = context.vm;
    // Create the builtin cost segment, with dummy values.
    let builtin_cost_segment = vm.add_memory_segment();
    for token_type in CostTokenType::iter_precost() {
        vm.insert_value(
            (builtin_cost_segment + (token_type.offset_in_builtin_costs() as usize)).unwrap(),
            Felt252::from(token_gas_cost(*token_type)),
        )
        .unwrap()
    }
    // Put a pointer to the builtin cost segment at the end of the program (after the
    // additional `ret` statement).
    vm.insert_value(
        (vm.get_pc() + context.data_len).unwrap(),
        builtin_cost_segment,
    )
    .unwrap();
}

#[allow(dead_code)]
fn print_bytecode(data: &[MaybeRelocatable]) {
    println!();
    println!("-------------- BYTECODE INSTRUCTIONS ----------------");
    println!();
    data.iter()
        .enumerate()
        .for_each(|(i, d)| println!("INSTRUCTION {}: {:?}", i, d));
}

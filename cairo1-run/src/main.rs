#![allow(unused_imports)]
use bincode::enc::write::Writer;
use cairo_lang_casm::{casm, casm_extend};
use cairo_lang_compiler::{compile_cairo_project_at_path, CompilerConfig};
use cairo_lang_runner::RunnerError as CairoLangRunnerError;
use cairo_lang_runner::{
    build_hints_dict, casm_run::RunFunctionContext, token_gas_cost, CairoHintProcessor,
    SierraCasmRunner, StarknetState,
};
use cairo_lang_sierra::{extensions::gas::CostTokenType, ProgramParser};
use cairo_lang_sierra_to_casm::compiler::CompilationError;
use cairo_lang_sierra_to_casm::metadata::MetadataError;
use cairo_lang_sierra_to_casm::{compiler::compile, metadata::calc_metadata};
use cairo_lang_utils::ordered_hash_map::OrderedHashMap;
use cairo_vm::air_public_input::PublicInputError;
use cairo_vm::cairo_run;
use cairo_vm::cairo_run::EncodeTraceError;
use cairo_vm::types::errors::program_errors::ProgramError;

use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::runner_errors::RunnerError;
use cairo_vm::vm::errors::trace_errors::TraceError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::{
    felt::Felt252,
    serde::deserialize_program::ReferenceManager,
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{
        runners::cairo_runner::{CairoRunner, RunResources},
        vm_core::VirtualMachine,
    },
};
use clap::{CommandFactory, Parser, ValueHint};
use itertools::chain;
use std::io::BufWriter;
use std::io::Write;
use std::path::PathBuf;
use std::{collections::HashMap, io, path::Path};
use thiserror::Error;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath)]
    filename: PathBuf,
    #[clap(long = "trace_file", value_parser)]
    trace_file: Option<PathBuf>,
    #[structopt(long = "memory_file")]
    memory_file: Option<PathBuf>,
    #[clap(long = "layout", default_value = "plain", value_parser=validate_layout)]
    layout: String,
}

fn validate_layout(value: &str) -> Result<String, String> {
    match value {
        "plain"
        | "small"
        | "dex"
        | "starknet"
        | "starknet_with_keccak"
        | "recursive_large_output"
        | "all_cairo"
        | "all_solidity"
        | "dynamic" => Ok(value.to_string()),
        _ => Err(format!("{value} is not a valid layout")),
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("Invalid arguments")]
    Cli(#[from] clap::Error),
    #[error("Failed to interact with the file system")]
    IO(#[from] std::io::Error),
    #[error("The cairo program execution failed")]
    CairoRunner(#[from] CairoLangRunnerError),
    #[error(transparent)]
    EncodeTrace(#[from] EncodeTraceError),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
    #[error(transparent)]
    Trace(#[from] TraceError),
    #[error(transparent)]
    PublicInput(#[from] PublicInputError),
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Compilation(#[from] Box<CompilationError>),
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
}

pub struct FileWriter {
    buf_writer: io::BufWriter<std::fs::File>,
    bytes_written: usize,
}

impl Writer for FileWriter {
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

fn run(args: impl Iterator<Item = String>) -> Result<(), Error> {
    let args = Args::try_parse_from(args)?;

    let compiler_config = CompilerConfig {
        replace_ids: true,
        ..CompilerConfig::default()
    };
    let sierra_program =
        compile_cairo_project_at_path(&args.filename, compiler_config).unwrap();

    // variable needed for the SierraCasmRunner
    let contracts_info = OrderedHashMap::default();

    // We need this runner to use the `find_function` method for main().
    let casm_runner = SierraCasmRunner::new(
        sierra_program.clone(),
        Some(Default::default()),
        contracts_info,
    )?;

    let main_func = casm_runner.find_function("::main")?;
    let initial_gas = 9999999999999_usize;

    // Entry code and footer are part of the whole instructions that are
    // ran by the VM.
    let (entry_code, builtins) = casm_runner.create_entry_code(main_func, &[], initial_gas)?;

    let mut ctx = casm! {};
    casm_extend! {ctx,
        call rel 4;
        jmp rel 0;
    };

    let footer = casm_runner.create_code_footer();

    let check_gas_usage = false;
    let metadata = calc_metadata(&sierra_program, Default::default())?;
    let casm_program = compile(&sierra_program, &metadata, check_gas_usage)?;

    let instructions = chain!(
        ctx.instructions.iter(),
        casm_program.instructions.iter(),
        // footer.iter()
    );

    let (hints_dict, string_to_hint) = build_hints_dict(instructions.clone());

    let inst_vec: Vec<&cairo_lang_casm::instructions::Instruction> = instructions.collect();

    println!("Instructions: {:?}", inst_vec);
    println!("Inst len: {}", inst_vec.len());

    let instructions = chain!(
        ctx.instructions.iter(),
        casm_program.instructions.iter(),
        footer.iter()
    );

    let data: Vec<MaybeRelocatable> = instructions
        .flat_map(|inst| inst.assemble().encode())
        .map(Felt252::from)
        .map(MaybeRelocatable::from)
        .collect();

    let data_len = data.len();
    println!("////\n");

    println!("Data len: {}", data.len());

    let mut program = Program::new_for_proof(
        vec![],
        data,
        0,
        2,
        hints_dict,
        ReferenceManager {
            references: Vec::new(),
        },
        HashMap::new(),
        vec![],
        None,
    )?;

    let mut runner = CairoRunner::new(&program, "plain", true)?;

    let mut vm = VirtualMachine::new(true);
    let end = runner.initialize(&mut vm)?;

    // Cairo lang runner error
    let function_context = RunFunctionContext {
        vm: &mut vm,
        data_len,
    };

    // additional_initialization(function_context)?;

    let mut hint_processor = CairoHintProcessor {
        runner: None,
        string_to_hint,
        starknet_state: StarknetState::default(),
        // This is failing
        run_resources: RunResources::default(),
    };

    println!("End: {:?}\n", end);

    println!("//// Starting execution \n");

    runner
        .run_until_pc(end, &mut vm, &mut hint_processor)
        .unwrap();
    runner
        .run_for_steps(1, &mut vm, &mut hint_processor)
        .unwrap();
    // Maybe this is not needed
    runner
        .end_run(false, false, &mut vm, &mut hint_processor)
        .unwrap();
    runner.read_return_values(&mut vm).unwrap();
    runner.relocate(&mut vm, true).unwrap();

    let relocated_trace = vm.get_relocated_trace()?;
    if args.trace_file.is_some() {
        let trace_path = args.trace_file.unwrap();
        let trace_file = std::fs::File::create(trace_path)?;
        let mut trace_writer =
            FileWriter::new(io::BufWriter::with_capacity(3 * 1024 * 1024, trace_file));

        cairo_run::write_encoded_trace(relocated_trace, &mut trace_writer)?;
        trace_writer.flush()?;
    }
    if args.memory_file.is_some() {
        let memory_path = args.memory_file.unwrap();
        let memory_file = std::fs::File::create(memory_path).unwrap();
        let mut memory_writer =
            FileWriter::new(io::BufWriter::with_capacity(5 * 1024 * 1024, memory_file));

        cairo_run::write_encoded_memory(&runner.relocated_memory, &mut memory_writer)?;
        memory_writer.flush().unwrap();
    }

    println!(
        "Pub input: \n {:?}",
        runner.get_air_public_input(&vm).unwrap()
    );
    Ok(())
}

/*
fn additional_initialization(context: RunFunctionContext) -> Result<(), Error> {
    let vm = context.vm;
    // Create the builtin cost segment
    let builtin_cost_segment = vm.add_memory_segment();
    for token_type in CostTokenType::iter_precost() {
        vm.insert_value(
            (builtin_cost_segment + (token_type.offset_in_builtin_costs() as usize)).unwrap(),
            Felt252::from(token_gas_cost(*token_type)),
        )?
    }
    // Put a pointer to the builtin cost segment at the end of the program (after the
    // additional `ret` statement).
    /*
    vm.insert_value(
        (vm.get_pc() + context.data_len).unwrap(),
        builtin_cost_segment,
    )?;
    */

    Ok(())
}
*/

fn main() -> Result<(), Error> {
    match run(std::env::args()) {
        Err(Error::Cli(err)) => err.exit(),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_arguments)]
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/fibonacci.cairo", "--trace_file", "/dev/null", "--memory_file", "/dev/null"].as_slice())]
    fn test_run_fibonacci_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(()));
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/factorial.cairo", "--trace_file", "/dev/null", "--memory_file", "/dev/null"].as_slice())]
    fn test_run_factorial_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(()));
    }
}

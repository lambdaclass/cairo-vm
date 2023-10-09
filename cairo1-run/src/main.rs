#![allow(unused_imports)]
use bincode::enc::write::Writer;
use cairo_lang_compiler::{compile_cairo_project_at_path, CompilerConfig};
use cairo_lang_runner::RunnerError as CairoLangRunnerError;
use cairo_lang_runner::{
    build_hints_dict, casm_run::RunFunctionContext, token_gas_cost, CairoHintProcessor,
    SierraCasmRunner, StarknetState,
};
use cairo_lang_sierra::extensions::core::{CoreLibfunc, CoreType};
use cairo_lang_sierra::program_registry::ProgramRegistry;
use cairo_lang_sierra::{extensions::gas::CostTokenType, ProgramParser};
use cairo_lang_sierra_to_casm::compiler::CompilationError;
use cairo_lang_sierra_to_casm::metadata::MetadataError;
use cairo_lang_sierra_to_casm::{compiler::compile, metadata::calc_metadata};
use cairo_lang_sierra_type_size::get_type_size_map;
use cairo_lang_utils::ordered_hash_map::OrderedHashMap;
use cairo_vm::air_public_input::PublicInputError;
use cairo_vm::cairo_run;
use cairo_vm::cairo_run::EncodeTraceError;
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::relocatable::Relocatable;
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
use itertools::{chain, Itertools};
use std::borrow::Cow;
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
    #[error("Program panicked with {0:?}")]
    RunPanic(Vec<Felt252>),
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

fn run(args: impl Iterator<Item = String>) -> Result<Vec<MaybeRelocatable>, Error> {
    let args = Args::try_parse_from(args)?;

    let compiler_config = CompilerConfig {
        replace_ids: true,
        ..CompilerConfig::default()
    };
    let sierra_program =
        (*compile_cairo_project_at_path(&args.filename, compiler_config).unwrap()).clone();

    // variable needed for the SierraCasmRunner
    let contracts_info = OrderedHashMap::default();

    // We need this runner to use the `find_function` method for main().
    let casm_runner = SierraCasmRunner::new(
        sierra_program.clone(),
        Some(Default::default()),
        contracts_info,
    )?;

    let sierra_program_registry =
        ProgramRegistry::<CoreType, CoreLibfunc>::new(&sierra_program).unwrap();
    let type_sizes = get_type_size_map(&sierra_program, &sierra_program_registry).unwrap();

    let main_func = casm_runner.find_function("::main")?;

    let initial_gas = 9999999999999_usize;

    // Entry code and footer are part of the whole instructions that are
    // ran by the VM.
    let (entry_code, builtins) = casm_runner.create_entry_code(main_func, &[], initial_gas)?;
    let footer = casm_runner.create_code_footer();

    let check_gas_usage = true;
    let metadata = calc_metadata(&sierra_program, Default::default())?;
    let casm_program = compile(&sierra_program, &metadata, check_gas_usage)?;

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
    )?;

    let mut runner = CairoRunner::new(&program, "all_cairo", false)?;
    let mut vm = VirtualMachine::new(true);
    let end = runner.initialize(&mut vm)?;

    let function_context = RunFunctionContext {
        vm: &mut vm,
        data_len,
    };

    additional_initialization(function_context)?;

    let mut hint_processor = CairoHintProcessor {
        runner: None,
        string_to_hint,
        starknet_state: StarknetState::default(),
        run_resources: RunResources::default(),
    };

    runner.run_until_pc(end, &mut vm, &mut hint_processor)?;
    runner.end_run(true, false, &mut vm, &mut hint_processor)?;

    // Fetch return type data
    let return_type_id = main_func.signature.ret_types.last().unwrap();
    let return_type_size = type_sizes.get(&return_type_id).cloned().unwrap_or_default();

    let mut return_values = vm.get_return_values(return_type_size as usize)?;
    // Check if this result is a Panic result
    if return_type_id
        .debug_name
        .as_ref()
        .unwrap()
        .starts_with("core::panics::PanicResult::")
    {
        // Check the failure flag (aka first return value)
        if *return_values.first().unwrap() != MaybeRelocatable::from(0) {
            // In case of failure, extract the error from teh return values (aka last two values)
            let panic_data_end = return_values
                .last()
                .unwrap()
                .get_relocatable()
                .ok_or(VirtualMachineError::Unexpected)?;
            let panic_data_start = return_values
                .get(return_values.len() - 2)
                .ok_or(VirtualMachineError::Unexpected)?
                .get_relocatable()
                .ok_or(VirtualMachineError::Unexpected)?;
            let panic_data = vm.get_integer_range(
                panic_data_start,
                (panic_data_end - panic_data_start).map_err(VirtualMachineError::Math)?,
            )?;
            return Err(Error::RunPanic(
                panic_data.iter().map(|c| c.as_ref().clone()).collect(),
            ));
        } else {
            return_values = return_values[2..].to_vec()
        }
    }

    runner.relocate(&mut vm, true)?;

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

    Ok(return_values)
}

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
    vm.insert_value(
        (vm.get_pc() + context.data_len).unwrap(),
        builtin_cost_segment,
    )?;

    Ok(())
}

fn main() -> Result<(), Error> {
    match run(std::env::args()) {
        Err(Error::Cli(err)) => err.exit(),
        Ok(return_values) => {
            if !return_values.is_empty() {
                let return_values_string_list =
                    return_values.iter().map(|m| m.to_string()).join(", ");
                println!("Return values : [{}]", return_values_string_list);
            }
            Ok(())
        }
        Err(Error::RunPanic(panic_data)) => {
            if !panic_data.is_empty() {
                let panic_data_string_list = panic_data
                    .iter()
                    .map(|m| {
                        // Try to parse to utf8 string
                        let msg = String::from_utf8(m.to_be_bytes().to_vec());
                        if let Ok(msg) = msg {
                            format!("{} ('{}')", m.to_string(), msg)
                        } else {
                            m.to_string()
                        }
                    })
                    .join(", ");
                println!("Run panicked with: [{}]", panic_data_string_list);
            }
            Ok(())
        }
        Err(err) => Err(err),
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
        assert_matches!(run(args), Ok(res) if res == vec![MaybeRelocatable::from(89)]);
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/factorial.cairo", "--trace_file", "/dev/null", "--memory_file", "/dev/null"].as_slice())]
    fn test_run_factorial_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(res) if res == vec![MaybeRelocatable::from(3628800)]);
    }
}

use bincode::enc::write::Writer;
use cairo_lang_compiler::{compile_cairo_project_at_path, CompilerConfig};
use cairo_lang_sierra::{ids::ConcreteTypeId, program_registry::ProgramRegistryError};
use cairo_lang_sierra_to_casm::{compiler::CompilationError, metadata::MetadataError};
use cairo_run::Cairo1RunConfig;
use cairo_vm::{
    air_public_input::PublicInputError,
    cairo_run::EncodeTraceError,
    types::{errors::program_errors::ProgramError, relocatable::MaybeRelocatable},
    vm::{
        errors::{
            memory_errors::MemoryError, runner_errors::RunnerError, trace_errors::TraceError,
            vm_errors::VirtualMachineError,
        },
        vm_core::VirtualMachine,
    },
    Felt252,
};
use clap::{Parser, ValueHint};
use itertools::Itertools;
use std::{
    io::{self, Write},
    iter::Peekable,
    path::PathBuf,
    slice::Iter,
};
use thiserror::Error;

pub mod cairo_run;

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
    #[clap(long = "proof_mode", value_parser)]
    proof_mode: bool,
    #[clap(long = "air_public_input", requires = "proof_mode")]
    air_public_input: Option<PathBuf>,
    #[clap(
        long = "air_private_input",
        requires_all = ["proof_mode", "trace_file", "memory_file"] 
    )]
    air_private_input: Option<PathBuf>,
    #[clap(
        long = "cairo_pie_output",
        // We need to add these air_private_input & air_public_input or else
        // passing cairo_pie_output + either of these without proof_mode will not fail
        conflicts_with_all = ["proof_mode", "air_private_input", "air_public_input"]
    )]
    cairo_pie_output: Option<PathBuf>,
    // Arguments should be spaced, with array elements placed between brackets
    // For example " --args '1 2 [1 2 3]'" will yield 3 arguments, with the last one being an array of 3 elements
    #[clap(long = "args", default_value = "", value_parser=process_args)]
    args: FuncArgs,
    #[clap(long = "print_output", value_parser)]
    print_output: bool,
}

#[derive(Debug, Clone)]
pub enum FuncArg {
    Array(Vec<Felt252>),
    Single(Felt252),
}

#[derive(Debug, Clone, Default)]
struct FuncArgs(Vec<FuncArg>);

fn process_args(value: &str) -> Result<FuncArgs, String> {
    if value.is_empty() {
        return Ok(FuncArgs::default());
    }
    let mut args = Vec::new();
    let mut input = value.split(' ');
    while let Some(value) = input.next() {
        // First argument in an array
        if value.starts_with('[') {
            let mut array_arg =
                vec![Felt252::from_dec_str(value.strip_prefix('[').unwrap()).unwrap()];
            // Process following args in array
            let mut array_end = false;
            while !array_end {
                if let Some(value) = input.next() {
                    // Last arg in array
                    if value.ends_with(']') {
                        array_arg
                            .push(Felt252::from_dec_str(value.strip_suffix(']').unwrap()).unwrap());
                        array_end = true;
                    } else {
                        array_arg.push(Felt252::from_dec_str(value).unwrap())
                    }
                }
            }
            // Finalize array
            args.push(FuncArg::Array(array_arg))
        } else {
            // Single argument
            args.push(FuncArg::Single(Felt252::from_dec_str(value).unwrap()))
        }
    }
    Ok(FuncArgs(args))
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
pub enum Error {
    #[error("Invalid arguments")]
    Cli(#[from] clap::Error),
    #[error("Failed to interact with the file system")]
    IO(#[from] std::io::Error),
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
    ProgramRegistry(#[from] Box<ProgramRegistryError>),
    #[error(transparent)]
    Compilation(#[from] Box<CompilationError>),
    #[error("Failed to compile to sierra:\n {0}")]
    SierraCompilation(String),
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error("Program panicked with {0:?}")]
    RunPanic(Vec<Felt252>),
    #[error("Function signature has no return types")]
    NoRetTypesInSignature,
    #[error("No size for concrete type id: {0}")]
    NoTypeSizeForId(ConcreteTypeId),
    #[error("Concrete type id has no debug name: {0}")]
    TypeIdNoDebugName(ConcreteTypeId),
    #[error("No info in sierra program registry for concrete type id: {0}")]
    NoInfoForType(ConcreteTypeId),
    #[error("Failed to extract return values from VM")]
    FailedToExtractReturnValues,
    #[error("Function expects arguments of size {expected} and received {actual} instead.")]
    ArgumentsSizeMismatch { expected: i16, actual: i16 },
    #[error("Function param {param_index} only partially contains argument {arg_index}.")]
    ArgumentUnaligned {
        param_index: usize,
        arg_index: usize,
    },
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

fn run(args: impl Iterator<Item = String>) -> Result<Option<String>, Error> {
    let args = Args::try_parse_from(args)?;

    let cairo_run_config = Cairo1RunConfig {
        proof_mode: args.proof_mode,
        relocate_mem: args.memory_file.is_some() || args.air_public_input.is_some(),
        layout: &args.layout,
        trace_enabled: args.trace_file.is_some() || args.air_public_input.is_some(),
        args: &args.args.0,
        finalize_builtins: args.air_private_input.is_some() || args.cairo_pie_output.is_some(),
    };

    let compiler_config = CompilerConfig {
        replace_ids: true,
        ..CompilerConfig::default()
    };

    let sierra_program = compile_cairo_project_at_path(&args.filename, compiler_config)
        .map_err(|err| Error::SierraCompilation(err.to_string()))?;

    let (runner, vm, return_values) =
        cairo_run::cairo_run_program(&sierra_program, cairo_run_config)?;

    let output_string = if args.print_output {
        Some(serialize_output(&vm, &return_values))
    } else {
        None
    };

    if let Some(file_path) = args.air_public_input {
        let json = runner.get_air_public_input(&vm)?.serialize_json()?;
        std::fs::write(file_path, json)?;
    }

    if let (Some(file_path), Some(trace_file), Some(memory_file)) = (
        args.air_private_input,
        args.trace_file.clone(),
        args.memory_file.clone(),
    ) {
        // Get absolute paths of trace_file & memory_file
        let trace_path = trace_file
            .as_path()
            .canonicalize()
            .unwrap_or(trace_file.clone())
            .to_string_lossy()
            .to_string();
        let memory_path = memory_file
            .as_path()
            .canonicalize()
            .unwrap_or(memory_file.clone())
            .to_string_lossy()
            .to_string();

        let json = runner
            .get_air_private_input(&vm)
            .to_serializable(trace_path, memory_path)
            .serialize_json()
            .map_err(PublicInputError::Serde)?;
        std::fs::write(file_path, json)?;
    }

    if let Some(ref file_path) = args.cairo_pie_output {
        runner.get_cairo_pie(&vm)?.write_zip_file(file_path)?
    }

    if let Some(trace_path) = args.trace_file {
        let relocated_trace = runner
            .relocated_trace
            .ok_or(Error::Trace(TraceError::TraceNotRelocated))?;
        let trace_file = std::fs::File::create(trace_path)?;
        let mut trace_writer =
            FileWriter::new(io::BufWriter::with_capacity(3 * 1024 * 1024, trace_file));

        cairo_vm::cairo_run::write_encoded_trace(&relocated_trace, &mut trace_writer)?;
        trace_writer.flush()?;
    }
    if let Some(memory_path) = args.memory_file {
        let memory_file = std::fs::File::create(memory_path)?;
        let mut memory_writer =
            FileWriter::new(io::BufWriter::with_capacity(5 * 1024 * 1024, memory_file));

        cairo_vm::cairo_run::write_encoded_memory(&runner.relocated_memory, &mut memory_writer)?;
        memory_writer.flush()?;
    }

    Ok(output_string)
}

fn main() -> Result<(), Error> {
    match run(std::env::args()) {
        Err(Error::Cli(err)) => err.exit(),
        Ok(output) => {
            if let Some(output_string) = output {
                println!("Program Output : {}", output_string);
            }
            Ok(())
        }
        Err(Error::RunPanic(panic_data)) => {
            if !panic_data.is_empty() {
                let panic_data_string_list = panic_data
                    .iter()
                    .map(|m| {
                        // Try to parse to utf8 string
                        let msg = String::from_utf8(m.to_bytes_be().to_vec());
                        if let Ok(msg) = msg {
                            format!("{} ('{}')", m, msg)
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

#[allow(clippy::type_complexity)]
fn build_hints_vec<'b>(
    instructions: impl Iterator<Item = &'b Instruction>,
) -> (Vec<(usize, Vec<Hint>)>, HashMap<usize, Vec<HintParams>>) {
    let mut hints: Vec<(usize, Vec<Hint>)> = Vec::new();
    let mut program_hints: HashMap<usize, Vec<HintParams>> = HashMap::new();

    let mut hint_offset = 0;

    for instruction in instructions {
        if !instruction.hints.is_empty() {
            hints.push((hint_offset, instruction.hints.clone()));
            program_hints.insert(
                hint_offset,
                vec![HintParams {
                    code: hint_offset.to_string(),
                    accessible_scopes: Vec::new(),
                    flow_tracking_data: FlowTrackingData {
                        ap_tracking: ApTracking::default(),
                        reference_ids: HashMap::new(),
                    },
                }],
            );
        }
        hint_offset += instruction.body.op_size();
    }
    (hints, program_hints)
}

/// Finds first function ending with `name_suffix`.
fn find_function<'a>(
    sierra_program: &'a SierraProgram,
    name_suffix: &'a str,
) -> Result<&'a Function, RunnerError> {
    sierra_program
        .funcs
        .iter()
        .find(|f| {
            if let Some(name) = &f.id.debug_name {
                name.ends_with(name_suffix)
            } else {
                false
            }
        })
        .ok_or_else(|| RunnerError::MissingMain)
}

/// Creates a list of instructions that will be appended to the program's bytecode.
fn create_code_footer() -> Vec<Instruction> {
    casm! {
        // Add a `ret` instruction used in libfuncs that retrieve the current value of the `fp`
        // and `pc` registers.
        ret;
    }
    .instructions
}

/// Returns the instructions to add to the beginning of the code to successfully call the main
/// function, as well as the builtins required to execute the program.
fn create_entry_code(
    sierra_program_registry: &ProgramRegistry<CoreType, CoreLibfunc>,
    casm_program: &CairoProgram,
    type_sizes: &UnorderedHashMap<ConcreteTypeId, i16>,
    func: &Function,
    initial_gas: usize,
    proof_mode: bool,
    args: &Vec<FuncArg>,
) -> Result<(Vec<Instruction>, Vec<BuiltinName>), Error> {
    let mut ctx = casm! {};
    // The builtins in the formatting expected by the runner.
    let (builtins, builtin_offset) = get_function_builtins(func, proof_mode);

    // Load all vecs to memory.
    // Load all array args content to memory.
    let mut array_args_data = vec![];
    let mut ap_offset: i16 = 0;
    for arg in args {
        let FuncArg::Array(values) = arg else {
            continue;
        };
        array_args_data.push(ap_offset);
        casm_extend! {ctx,
            %{ memory[ap + 0] = segments.add() %}
            ap += 1;
        }
        for (i, v) in values.iter().enumerate() {
            let arr_at = (i + 1) as i16;
            casm_extend! {ctx,
                [ap + 0] = (v.to_bigint());
                [ap + 0] = [[ap - arr_at] + (i as i16)], ap++;
            };
        }
        ap_offset += (1 + values.len()) as i16;
    }
    let mut array_args_data_iter = array_args_data.iter();
    let after_arrays_data_offset = ap_offset;
    let mut arg_iter = args.iter().enumerate();
    let mut param_index = 0;
    let mut expected_arguments_size = 0;
    if func.signature.param_types.iter().any(|ty| {
        get_info(sierra_program_registry, ty)
            .map(|x| x.long_id.generic_id == SegmentArenaType::ID)
            .unwrap_or_default()
    }) {
        casm_extend! {ctx,
            // SegmentArena segment.
            %{ memory[ap + 0] = segments.add() %}
            // Infos segment.
            %{ memory[ap + 1] = segments.add() %}
            ap += 2;
            [ap + 0] = 0, ap++;
            // Write Infos segment, n_constructed (0), and n_destructed (0) to the segment.
            [ap - 2] = [[ap - 3]];
            [ap - 1] = [[ap - 3] + 1];
            [ap - 1] = [[ap - 3] + 2];
        }
        ap_offset += 3;
    }
    for ty in func.signature.param_types.iter() {
        let info = get_info(sierra_program_registry, ty)
            .ok_or_else(|| Error::NoInfoForType(ty.clone()))?;
        let generic_ty = &info.long_id.generic_id;
        if let Some(offset) = builtin_offset.get(generic_ty) {
            let mut offset = *offset;
            if proof_mode {
                // Everything is off by 2 due to the proof mode header
                offset += 2;
            }
            casm_extend! {ctx,
                [ap + 0] = [fp - offset], ap++;
            }
            ap_offset += 1;
        } else if generic_ty == &SystemType::ID {
            casm_extend! {ctx,
                %{ memory[ap + 0] = segments.add() %}
                ap += 1;
            }
            ap_offset += 1;
        } else if generic_ty == &GasBuiltinType::ID {
            casm_extend! {ctx,
                [ap + 0] = initial_gas, ap++;
            }
            ap_offset += 1;
        } else if generic_ty == &SegmentArenaType::ID {
            let offset = -ap_offset + after_arrays_data_offset;
            casm_extend! {ctx,
                [ap + 0] = [ap + offset] + 3, ap++;
            }
            ap_offset += 1;
        } else {
            let ty_size = type_sizes[ty];
            let param_ap_offset_end = ap_offset + ty_size;
            expected_arguments_size += ty_size;
            while ap_offset < param_ap_offset_end {
                let Some((arg_index, arg)) = arg_iter.next() else {
                    break;
                };
                match arg {
                    FuncArg::Single(value) => {
                        casm_extend! {ctx,
                            [ap + 0] = (value.to_bigint()), ap++;
                        }
                        ap_offset += 1;
                    }
                    FuncArg::Array(values) => {
                        let offset = -ap_offset + array_args_data_iter.next().unwrap();
                        casm_extend! {ctx,
                            [ap + 0] = [ap + (offset)], ap++;
                            [ap + 0] = [ap - 1] + (values.len()), ap++;
                        }
                        ap_offset += 2;
                        if ap_offset > param_ap_offset_end {
                            return Err(Error::ArgumentUnaligned {
                                param_index,
                                arg_index,
                            });
                        }
                    }
                }
            }
            param_index += 1;
        };
    }
    let actual_args_size = args
        .iter()
        .map(|arg| match arg {
            FuncArg::Single(_) => 1,
            FuncArg::Array(_) => 2,
        })
        .sum::<i16>();
    if expected_arguments_size != actual_args_size {
        return Err(Error::ArgumentsSizeMismatch {
            expected: expected_arguments_size,
            actual: actual_args_size,
        });
    }

    let before_final_call = ctx.current_code_offset;
    let final_call_size = 3;
    let offset = final_call_size
        + casm_program.debug_info.sierra_statement_info[func.entry_point.0].code_offset;

    casm_extend! {ctx,
        call rel offset;
        ret;
    }
    assert_eq!(before_final_call + final_call_size, ctx.current_code_offset);

    Ok((ctx.instructions, builtins))
}

fn get_info<'a>(
    sierra_program_registry: &'a ProgramRegistry<CoreType, CoreLibfunc>,
    ty: &'a cairo_lang_sierra::ids::ConcreteTypeId,
) -> Option<&'a cairo_lang_sierra::extensions::types::TypeInfo> {
    sierra_program_registry
        .get_type(ty)
        .ok()
        .map(|ctc| ctc.info())
}

/// Creates the metadata required for a Sierra program lowering to casm.
fn create_metadata(
    sierra_program: &cairo_lang_sierra::program::Program,
    metadata_config: Option<MetadataComputationConfig>,
) -> Result<Metadata, VirtualMachineError> {
    if let Some(metadata_config) = metadata_config {
        calc_metadata(sierra_program, metadata_config).map_err(|err| match err {
            MetadataError::ApChangeError(_) => VirtualMachineError::Unexpected,
            MetadataError::CostError(_) => VirtualMachineError::Unexpected,
        })
    } else {
        Ok(Metadata {
            ap_change_info: calc_ap_changes(sierra_program, |_, _| 0)
                .map_err(|_| VirtualMachineError::Unexpected)?,
            gas_info: GasInfo {
                variable_values: Default::default(),
                function_costs: Default::default(),
            },
        })
    }
}

/// Type representing the Output builtin.
#[derive(Default)]
pub struct OutputType {}
impl cairo_lang_sierra::extensions::NoGenericArgsGenericType for OutputType {
    const ID: cairo_lang_sierra::ids::GenericTypeId =
        cairo_lang_sierra::ids::GenericTypeId::new_inline("Output");
    const STORABLE: bool = true;
    const DUPLICATABLE: bool = false;
    const DROPPABLE: bool = false;
    const ZERO_SIZED: bool = false;
}

fn get_function_builtins(
    func: &Function,
    proof_mode: bool,
) -> (
    Vec<BuiltinName>,
    HashMap<cairo_lang_sierra::ids::GenericTypeId, i16>,
) {
    let entry_params = &func.signature.param_types;
    let mut builtins = Vec::new();
    let mut builtin_offset: HashMap<cairo_lang_sierra::ids::GenericTypeId, i16> = HashMap::new();
    let mut current_offset = 3;
    // Fetch builtins from the entry_params in the standard order
    if entry_params
        .iter()
        .any(|ti| ti.debug_name == Some("Poseidon".into()))
    {
        builtins.push(BuiltinName::poseidon);
        builtin_offset.insert(PoseidonType::ID, current_offset);
        current_offset += 1;
    }
    if entry_params
        .iter()
        .any(|ti| ti.debug_name == Some("EcOp".into()))
    {
        builtins.push(BuiltinName::ec_op);
        builtin_offset.insert(EcOpType::ID, current_offset);
        current_offset += 1
    }
    if entry_params
        .iter()
        .any(|ti| ti.debug_name == Some("Bitwise".into()))
    {
        builtins.push(BuiltinName::bitwise);
        builtin_offset.insert(BitwiseType::ID, current_offset);
        current_offset += 1;
    }
    if entry_params
        .iter()
        .any(|ti| ti.debug_name == Some("RangeCheck".into()))
    {
        builtins.push(BuiltinName::range_check);
        builtin_offset.insert(RangeCheckType::ID, current_offset);
        current_offset += 1;
    }
    if entry_params
        .iter()
        .any(|ti| ti.debug_name == Some("Pedersen".into()))
    {
        builtins.push(BuiltinName::pedersen);
        builtin_offset.insert(PedersenType::ID, current_offset);
        current_offset += 1;
    }
    // Force an output builtin so that we can write the program output into it's segment
    if proof_mode {
        builtins.push(BuiltinName::output);
        builtin_offset.insert(OutputType::ID, current_offset);
    }
    builtins.reverse();
    (builtins, builtin_offset)
}

fn serialize_output(vm: &VirtualMachine, return_values: &[MaybeRelocatable]) -> String {
    let mut output_string = String::new();
    let mut return_values_iter: Peekable<Iter<MaybeRelocatable>> = return_values.iter().peekable();
    serialize_output_inner(&mut return_values_iter, &mut output_string, vm);
    fn serialize_output_inner(
        iter: &mut Peekable<Iter<MaybeRelocatable>>,
        output_string: &mut String,
        vm: &VirtualMachine,
    ) {
        while let Some(val) = iter.next() {
            if let MaybeRelocatable::RelocatableValue(x) = val {
                // Check if the next value is a relocatable of the same index
                if let Some(MaybeRelocatable::RelocatableValue(y)) = iter.peek() {
                    // Check if the two relocatable values represent a valid array in memory
                    if x.segment_index == y.segment_index && x.offset <= y.offset {
                        // Fetch the y value from the iterator so we don't serialize it twice
                        iter.next();
                        // Fetch array
                        maybe_add_whitespace(output_string);
                        output_string.push('[');
                        let array = vm.get_continuous_range(*x, y.offset - x.offset).unwrap();
                        let mut array_iter: Peekable<Iter<MaybeRelocatable>> =
                            array.iter().peekable();
                        serialize_output_inner(&mut array_iter, output_string, vm);
                        output_string.push(']');
                        continue;
                    }
                }
            }
            maybe_add_whitespace(output_string);
            output_string.push_str(&val.to_string());
        }
    }

    fn maybe_add_whitespace(string: &mut String) {
        if !string.is_empty() && !string.ends_with('[') {
            string.push(' ');
        }
    }
    output_string
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/fibonacci.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/fibonacci.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_fibonacci_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "89");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/factorial.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/factorial.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_factorial_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "3628800");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/array_get.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/array_get.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_array_get_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "3");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/enum_flow.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/enum_flow.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_enum_flow_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "300");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/enum_match.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/enum_match.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_enum_match_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "10 3618502788666131213697322783095070105623107215331596699973092056135872020471");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/hello.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/hello.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_hello_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1 1234");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/ops.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/ops.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_ops_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "6");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/print.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/print.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_print_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res.is_empty());
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/recursion.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/recursion.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_recursion_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1154076154663935037074198317650845438095734251249125412074882362667803016453");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/sample.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/sample.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_sample_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "5050");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/poseidon.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/poseidon.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_poseidon_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1099385018355113290651252669115094675591288647745213771718157553170111442461");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/poseidon_pedersen.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/poseidon_pedersen.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_poseidon_pedersen_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1036257840396636296853154602823055519264738423488122322497453114874087006398");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/pedersen_example.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/pedersen_example.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_pedersen_example_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1089549915800264549621536909767699778745926517555586332772759280702396009108");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/simple.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/simple.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_simple_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/simple_struct.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/simple_struct.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_simple_struct_ok(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "100");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/dictionaries.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/dictionaries.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_run_dictionaries(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1024");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null", "--args", "0"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null", "--args", "0"].as_slice())]
    fn test_run_branching_0(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null", "--args", "17"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null", "--args", "96"].as_slice())]
    fn test_run_branching_not_0(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "0");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--layout", "all_cairo", "--proof_mode"].as_slice())]
    fn test_run_branching_no_args(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Err(Error::ArgumentsSizeMismatch { expected, actual }) if expected == 1 && actual == 0);
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--layout", "all_cairo","--args", "1 2 3"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/branching.cairo", "--layout", "all_cairo", "--proof_mode", "--args", "1 2 3"].as_slice())]
    fn test_run_branching_too_many_args(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Err(Error::ArgumentsSizeMismatch { expected, actual }) if expected == 1 && actual == 3);
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/array_input_sum.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null", "--args", "2 [1 2 3 4] 0 [9 8]"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/array_input_sum.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null", "--args", "2 [1 2 3 4] 0 [9 8]"].as_slice())]
    fn test_array_input_sum(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "12");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/struct_span_return.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/struct_span_return.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null"].as_slice())]
    fn test_struct_span_return(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "[[4 3] [2 1]]");
    }

    #[rstest]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/tensor.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--cairo_pie_output", "/dev/null", "--args", "[2 2] [1 2 3 4]"].as_slice())]
    #[case(["cairo1-run", "../cairo_programs/cairo-1-programs/with_input/tensor.cairo", "--print_output", "--trace_file", "/dev/null", "--memory_file", "/dev/null", "--layout", "all_cairo", "--proof_mode", "--air_public_input", "/dev/null", "--air_private_input", "/dev/null", "--args", "[2 2] [1 2 3 4]"].as_slice())]
    fn test_tensor(#[case] args: &[&str]) {
        let args = args.iter().cloned().map(String::from);
        assert_matches!(run(args), Ok(Some(res)) if res == "1");
    }
}

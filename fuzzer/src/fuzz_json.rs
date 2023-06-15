use arbitrary::Arbitrary;
use bincode::enc::write::Writer;
use cairo_vm::cairo_run::{self, EncodeTraceError};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::trace_errors::TraceError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use honggfuzz::fuzz;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use thiserror::Error;

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

#[derive(Debug, Arbitrary)]
struct Args {
    program_content: Vec<u8>,
    trace_file: Option<PathBuf>,
    print_output: bool,
    entrypoint: String,
    memory_file: Option<PathBuf>,
    layout: Layout,
    proof_mode: bool,
    secure_run: Option<bool>,
}

#[derive(Debug, Arbitrary)]
enum Layout {
    Plain,
    Small,
    Dex,
    Starknet,
    StarknetWithKeccak,
    RecursiveLargeOutput,
    AllCairo,
    AllSolidity,
    Dynamic,
}

impl fmt::Display for Layout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Layout::Plain => write!(f, "plain"),
            Layout::Small => write!(f, "small"),
            Layout::Dex => write!(f, "dex"),
            Layout::Starknet => write!(f, "starknet"),
            Layout::StarknetWithKeccak => write!(f, "starknet_with_keccak"),
            Layout::RecursiveLargeOutput => write!(f, "recursive_large_output"),
            Layout::AllCairo => write!(f, "all_cairo"),
            Layout::AllSolidity => write!(f, "all_solidity"),
            Layout::Dynamic => write!(f, "dynamic"),
        }
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("Failed to interact with the file system")]
    IO(#[from] std::io::Error),
    #[error("The cairo program execution failed")]
    Runner(#[from] CairoRunError),
    #[error(transparent)]
    EncodeTrace(#[from] EncodeTraceError),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
    #[error(transparent)]
    Trace(#[from] TraceError),
}

struct FileWriter {
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

fn run(args: Args) -> Result<(), Error> {
    let trace_enabled = args.trace_file.is_some();
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        entrypoint: &args.entrypoint,
        trace_enabled,
        relocate_mem: args.memory_file.is_some(),
        layout: &args.layout.to_string(),
        proof_mode: args.proof_mode,
        secure_run: args.secure_run,
    };

    let (cairo_runner, mut vm) =
        match cairo_run::cairo_run(&args.program_content, &cairo_run_config, &mut hint_executor) {
            Ok(runner) => runner,
            Err(error) => {
                eprintln!("{error}");
                return Err(Error::Runner(error));
            }
        };

    if args.print_output {
        let mut output_buffer = "Program Output:\n".to_string();
        vm.write_output(&mut output_buffer)?;
        print!("{output_buffer}");
    }

    if let Some(trace_path) = args.trace_file {
        let relocated_trace = vm.get_relocated_trace()?;

        let trace_file = std::fs::File::create(trace_path)?;
        let mut trace_writer =
            FileWriter::new(io::BufWriter::with_capacity(3 * 1024 * 1024, trace_file));

        cairo_run::write_encoded_trace(relocated_trace, &mut trace_writer)?;
        trace_writer.flush()?;
    }

    if let Some(memory_path) = args.memory_file {
        let memory_file = std::fs::File::create(memory_path)?;
        let mut memory_writer =
            FileWriter::new(io::BufWriter::with_capacity(5 * 1024 * 1024, memory_file));

        cairo_run::write_encoded_memory(&cairo_runner.relocated_memory, &mut memory_writer)?;
        memory_writer.flush()?;
    }

    Ok(())
}

fn main() {
    loop {
        fuzz!(|args: Args| {
            let _ = run(args);
        });
    }
}

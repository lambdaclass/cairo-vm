#![deny(warnings)]
use bincode::enc::write::Writer;
use cairo_vm::cairo_run::{self, EncodeTraceError};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::trace_errors::TraceError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use clap::{Parser, ValueHint};
use std::io::{self, Write};
use std::path::PathBuf;
use thiserror::Error;

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath)]
    filename: PathBuf,
    #[clap(long = "--trace_file", value_parser)]
    trace_file: Option<PathBuf>,
    #[structopt(long = "--print_output")]
    print_output: bool,
    #[structopt(long = "--entrypoint", default_value = "main")]
    entrypoint: String,
    trace: Option<PathBuf>,
    #[structopt(long = "--memory_file")]
    memory_file: Option<PathBuf>,
    #[clap(long = "--layout", default_value = "plain", validator=validate_layout)]
    layout: String,
    #[structopt(long = "--proof_mode")]
    proof_mode: bool,
    #[structopt(long = "--secure_run")]
    secure_run: Option<bool>,
}

fn validate_layout(value: &str) -> Result<(), String> {
    match value {
        "plain" | "small" | "dex" | "bitwise" | "perpetual_with_bitwise" | "all" => Ok(()),
        _ => Err(format!("{value} is not a valid layout")),
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

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let trace_enabled = args.trace_file.is_some();
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        entrypoint: &args.entrypoint,
        trace_enabled,
        layout: &args.layout,
        proof_mode: args.proof_mode,
        secure_run: args.secure_run,
    };

    let program_content = std::fs::read(args.filename).map_err(|e| Error::IO(e))?;

    let (cairo_runner, mut vm) =
        match cairo_run::cairo_run(&program_content, &cairo_run_config, &mut hint_executor) {
            Ok(runner) => runner,
            Err(error) => {
                println!("{error}");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_layouts() {
        let valid_layouts = vec![
            "plain",
            "small",
            "dex",
            "bitwise",
            "perpetual_with_bitwise",
            "all",
        ];

        for layout in valid_layouts {
            assert_eq!(validate_layout(layout), Ok(()));
        }
    }

    #[test]
    fn test_invalid_layout() {
        let invalid_layout = "invalid layout name";
        assert!(validate_layout(invalid_layout).is_err());
    }
}

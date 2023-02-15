#![deny(warnings)]
use cairo_vm::cairo_run;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::errors::cairo_run_errors::CairoRunError;
use cairo_vm::vm::errors::runner_errors::RunnerError;
use cairo_vm::vm::errors::trace_errors::TraceError;
use clap::{Parser, ValueHint};
use std::path::PathBuf;

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

fn main() -> Result<(), CairoRunError> {
    let args = Args::parse();
    let trace_enabled = args.trace_file.is_some();
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        entrypoint: &args.entrypoint,
        trace_enabled,
        print_output: args.print_output,
        layout: &args.layout,
        proof_mode: args.proof_mode,
    };
    let cairo_runner = match cairo_run::cairo_run(
        &args.filename,
        &cairo_run_config,
        args.secure_run,
        &mut hint_executor,
    ) {
        Ok(runner) => runner,
        Err(error) => {
            println!("{error}");
            return Err(error);
        }
    };

    if let Some(trace_path) = args.trace_file {
        let relocated_trace = cairo_runner
            .relocated_trace
            .as_ref()
            .ok_or(CairoRunError::Trace(TraceError::TraceNotEnabled))?;
        match cairo_run::write_binary_trace(relocated_trace, &trace_path) {
            Ok(()) => (),
            Err(_e) => return Err(CairoRunError::Runner(RunnerError::WriteFail)),
        }
    }

    if let Some(memory_path) = args.memory_file {
        match cairo_run::write_binary_memory(&cairo_runner.relocated_memory, &memory_path) {
            Ok(()) => (),
            Err(_e) => return Err(CairoRunError::Runner(RunnerError::WriteFail)),
        }
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

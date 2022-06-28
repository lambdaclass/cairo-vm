#![deny(warnings)]
mod cairo_run;
mod math_utils;
mod serde;
mod types;
mod utils;
mod vm;
use crate::vm::errors::cairo_run_errors::CairoRunError;
use clap::{Parser, ValueHint};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath)]
    filename: PathBuf,
    #[clap(long, value_parser)]
    trace_file: Option<PathBuf>,
    #[clap(long)]
    program_output: bool,
}

fn main() -> Result<(), CairoRunError> {
    let args = Args::parse();
    let cairo_runner = match cairo_run::cairo_run(&args.filename) {
        Ok(runner) => runner,
        Err(error) => return Err(error),
    };

    if args.program_output {
        cairo_run::write_output(&cairo_runner);
    }

    if let Some(trace_path) = args.trace_file {
        cairo_run::write_binary_trace(&cairo_runner.relocated_trace, &trace_path);
    }

    Ok(())
}

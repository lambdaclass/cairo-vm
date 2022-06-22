#![deny(warnings)]
mod cairo_run;
mod math_utils;
mod serde;
mod types;
mod utils;
mod vm;
use clap::{Parser, ValueHint};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(value_parser, value_hint=ValueHint::FilePath)]
    filename: PathBuf,
}

fn main() {
    let args = Args::parse();
    cairo_run::cairo_run(&args.filename);
}

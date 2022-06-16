#![deny(warnings)]
mod cairo_run;
mod math_utils;
mod serde;
mod types;
mod utils;
mod vm;
use std::env;

fn main() {
    let mut args = env::args();
    let _executable = args.next();
    let filename = args.next().unwrap();

    cairo_run::cairo_run(&filename);
}

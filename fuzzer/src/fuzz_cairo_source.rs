use honggfuzz::fuzz;
mod utils;
use crate::utils::{run, Args};
use std::process::Command;

fn main() {
    loop {
        fuzz!(|data: (Args, Vec<u8>, [char; 50])| {
            let program_name: String = data.2.iter().collect();

            std::fs::write(&program_name, data.1).unwrap();

            Command::new("cairo-compile")
                .arg(&program_name)
                .arg("--cairo_path")
                .arg("hfuzz_workspace/fuzz_cairo/cairo_programs")
                .output()
                .expect("failed to execute process");

            let program_bytes = std::fs::read(&program_name).unwrap();

            let _ = run((data.0, program_bytes));

            std::fs::remove_file(program_name).unwrap();
        });
    }
}

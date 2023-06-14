use honggfuzz::fuzz;
mod utils;
use crate::utils::{run, Args};
use std::process::Command;

fn main() {
    loop {
        fuzz!(|data: (Args, Vec<u8>, [char; 50])| {
            let program_name: String = data.2.iter().collect();
            let mut cairo_path: String = "hfuzz_workspace/fuzz_cairo/cairo_programs".into();

            cairo_path.push_str(&program_name);

            std::fs::write(&program_name, data.1).unwrap();

            Command::new("cairo-compile")
                .arg(&cairo_path)
                .output()
                .expect("failed to execute process");

            let program_bytes = std::fs::read(&cairo_path).unwrap();

            let _ = run((data.0, program_bytes));

            std::fs::remove_file(cairo_path).unwrap();
        });
    }
}

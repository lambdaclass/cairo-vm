use crate::types::program::Program;
use crate::vm::runners::cairo_runner::CairoRunner;
use crate::vm::trace::trace_entry::RelocatedTraceEntry;
use bincode;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

pub fn cairo_run(path: &Path, trace_path: Option<&PathBuf>) {
    let program = Program::new(path);
    let mut cairo_runner = CairoRunner::new(&program);
    cairo_runner.initialize_segments(None);
    let end = cairo_runner.initialize_main_entrypoint().unwrap();
    cairo_runner.initialize_vm().unwrap();
    assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
    cairo_runner.vm.verify_auto_deductions().unwrap();
    cairo_runner.relocate().unwrap();
    if let Some(trace_path) = trace_path {
        write_binary_trace(&cairo_runner.relocated_trace, trace_path);
    }
    cairo_runner.write_output(&mut io::stdout()).unwrap();
}

#[allow(dead_code)]
/// Writes a trace as a binary file. Bincode encodes to little endian by default and each trace
/// entry is composed of 3 usize values that are padded to always reach 64 bit size.
fn write_binary_trace(relocated_trace: &Vec<RelocatedTraceEntry>, trace_file: &Path) {
    let mut buffer = File::create(trace_file).expect("Error while creating trace file");
    for (i, entry) in relocated_trace.iter().enumerate() {
        match bincode::serialize_into(&mut buffer, entry) {
            Ok(_) => {}
            Err(e) => println!(
                "Failed to dump trace at position {}, serialize error: {}",
                i, e
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_binary_file() {
        let program = Program::new("tests/support/struct.json");
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint().unwrap();
        cairo_runner.initialize_vm().unwrap();
        assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
        cairo_runner.relocate().unwrap();
        write_binary_trace(
            &cairo_runner.relocated_trace,
            "tests/support/struct_cleopatra.trace",
        );
    }
}

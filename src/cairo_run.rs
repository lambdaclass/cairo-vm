use crate::types::program::Program;
use crate::vm::errors::cairo_run_errors::CairoRunError;
use crate::vm::runners::cairo_runner::CairoRunner;
use crate::vm::trace::trace_entry::RelocatedTraceEntry;
use std::error;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

pub fn cairo_run(path: &Path, trace_path: Option<&PathBuf>) -> Result<(), CairoRunError> {
    let program = Program::new(path).unwrap();
    let mut cairo_runner = CairoRunner::new(&program);
    cairo_runner.initialize_segments(None);
    let end = cairo_runner.initialize_main_entrypoint()?;
    cairo_runner.initialize_vm()?;
    assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
    cairo_runner.vm.verify_auto_deductions()?;
    cairo_runner.relocate()?;
    if let Some(trace_path) = trace_path {
        write_binary_trace(&cairo_runner.relocated_trace, trace_path);
    }
    cairo_runner.write_output(&mut io::stdout()).unwrap();

    Ok(())
}

/// Writes a trace as a binary file. Bincode encodes to little endian by default and each trace
/// entry is composed of 3 usize values that are padded to always reach 64 bit size.
fn write_binary_trace(relocated_trace: &[RelocatedTraceEntry], trace_file: &Path) {
    let mut buffer = File::create(trace_file).expect("Error while creating trace file");
    for (i, entry) in relocated_trace.iter().enumerate() {
        if let Err(e) = bincode::serialize_into(&mut buffer, entry) {
            println!(
                "Failed to dump trace at position {}, serialize error: {}",
                i, e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_binary_file() {
        let program_path = Path::new("tests/support/struct.json");
        let serialized_trace_filename = "tests/support/struct_cleopatra.trace";
        let serialized_trace_path = Path::new(serialized_trace_filename.clone());
        let program = Program::new(program_path).expect("Couldn't open program");
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner
            .initialize_main_entrypoint()
            .expect("Couldn't initialize main entry point");
        cairo_runner
            .initialize_vm()
            .expect("Couldn't initialize VM");
        assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
        cairo_runner.relocate().expect("Couldn't relocate memory");
        write_binary_trace(&cairo_runner.relocated_trace, serialized_trace_path);

        let expected_trace_buffer = File::open("tests/support/struct.trace")
            .expect("Couldn't open python VM generated trace");
        let expected_trace: Vec<u8> = bincode::deserialize_from(&expected_trace_buffer)
            .expect("Couldn't deserialize python VM generated trace");
        let serialized_buffer =
            File::open(serialized_trace_filename).expect("Couldn't open rust VM generated trace");
        let serialized_program: Vec<u8> = bincode::deserialize_from(&serialized_buffer)
            .expect("Couldn't deserialize rust VM generated trace");

        assert!(expected_trace == serialized_program);
    }
}

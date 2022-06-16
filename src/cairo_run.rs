use crate::types::program::Program;
use crate::vm::runners::cairo_runner::CairoRunner;
use crate::vm::trace::trace_entry::RelocatedTraceEntry;
use std::io;
use bincode;

#[allow(dead_code)]
pub fn cairo_run(path: &str) {
    let program = Program::new(path);
    let mut cairo_runner = CairoRunner::new(&program);
    cairo_runner.initialize_segments(None);
    let end = cairo_runner.initialize_main_entrypoint().unwrap();
    cairo_runner.initialize_vm().unwrap();
    assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
    cairo_runner.relocate().unwrap();
    cairo_runner.write_output(&mut io::stdout());
}

#[allow(dead_code)]
/// Writes a trace as a binary file. Bincode defaults to little endian encoding and each trace
/// entry is composed of 3 usize values that are padded to always reach 64 bit size.
fn write_binary_trace(relocated_trace: &Vec<RelocatedTraceEntry>) {
    let binary_trace = bincode::serialize(relocated_trace);

    match binary_trace = {
        Ok(trace) => {},
        Err(e) => println!("Failed to dump trace, serialize error: {}", e),
    }
}

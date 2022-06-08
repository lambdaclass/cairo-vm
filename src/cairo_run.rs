use crate::types::program::Program;
use crate::vm::runners::cairo_runner::CairoRunner;
use std::io;

#[allow(dead_code)]
pub fn cairo_run(path: &str) {
    let program = Program::new(path);
    let mut cairo_runner = CairoRunner::new(&program);
    cairo_runner.initialize_segments(None);
    let end = cairo_runner.initialize_main_entrypoint();
    cairo_runner.initialize_vm();
    assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
    cairo_runner.relocate();
    cairo_runner.print_output(&mut io::stdout());
}

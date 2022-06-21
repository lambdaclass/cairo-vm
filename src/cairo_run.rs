use crate::types::program::Program;
use crate::vm::runners::cairo_runner::CairoRunner;
use std::io;
use std::{thread, time};

#[allow(dead_code)]
pub fn cairo_run(path: &str) {
    let ten_milli = time::Duration::from_millis(10);

    thread::sleep(ten_milli);

    let program = Program::new(path);
    let mut cairo_runner = CairoRunner::new(&program);
    cairo_runner.initialize_segments(None);
    let end = cairo_runner.initialize_main_entrypoint().unwrap();
    cairo_runner.initialize_vm().unwrap();
    assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
    cairo_runner.vm.verify_auto_deductions().unwrap();
    cairo_runner.relocate().unwrap();
    cairo_runner.write_output(&mut io::stdout()).unwrap();
}

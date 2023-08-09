use pyo3::{
    prelude::{pyfunction, PyResult, pymodule, wrap_pyfunction, Python, PyModule},
    exceptions::PyRuntimeError
};
use cairo_vm::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    cairo_run::{CairoRunConfig, cairo_run}
};

#[pyfunction]
fn cairo_run_dump_mem(json: String) -> PyResult<Vec<u8>> {
    let config = CairoRunConfig {
        relocate_mem: true,
        ..Default::default()
    };
    let mut hint_executor = BuiltinHintProcessor::new_empty();

    let (cairo_runner, _) = 
        cairo_run(&json.as_bytes(), &config, &mut hint_executor).map_err(|e| PyRuntimeError::new_err(format!{"{e:?}"}))?;
    
    let mut memory_dump = Vec::new();
    for (i, memory_cell) in cairo_runner.relocated_memory.iter().enumerate() {
        match memory_cell {
            None => continue,
            Some(unwrapped_memory_cell) => {
                memory_dump.extend_from_slice(&(i as u64).to_le_bytes());
                memory_dump.extend_from_slice(&unwrapped_memory_cell.to_le_bytes());
            }
        }
    }
    Ok(memory_dump)
}

#[pymodule]
fn cairo_vm_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cairo_run_dump_mem, m)?)?;
    Ok(())
}

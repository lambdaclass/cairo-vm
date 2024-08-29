mod utils;

use cairo1_run::{cairo_run_program, Cairo1RunConfig};
use cairo_vm::types::layout_name::LayoutName;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(msg: &str);
}

#[wasm_bindgen(start)]
pub fn start() {
    crate::utils::set_panic_hook();
}

// TODO: check why this is needed. Seems wasm-bindgen expects us to use
// `std::error::Error` even if it's not yet in `core`
macro_rules! wrap_error {
    ($xp: expr) => {
        $xp.map_err(|e| JsError::new(e.to_string().as_str()))
    };
}

#[wasm_bindgen(js_name = runCairoProgram)]
pub fn run_cairo_program() -> Result<String, JsError> {
    const PROGRAM: &[u8] = include_bytes!("../bitwise.sierra");

    let cairo_run_config = Cairo1RunConfig {
        layout: LayoutName::all_cairo,
        relocate_mem: true,
        trace_enabled: true,
        ..Default::default()
    };

    let sierra_program = serde_json::from_slice(PROGRAM)?;

    let (mut runner, _, _) = wrap_error!(cairo_run_program(
        &sierra_program,
        cairo_run_config,
    ))?;

    let mut buffer = String::new();

    wrap_error!(runner.vm.write_output(&mut buffer))?;

    log(buffer.as_str());

    Ok(buffer)
}

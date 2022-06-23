use crate::types::relocatable::MaybeRelocatable;
use crate::vm::runners::cairo_runner::CairoRunner;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use std::sync::{Arc, Mutex};
use wasmer::{imports, wat2wasm, Function, Instance, Module, Store, WasmerEnv};

pub fn execute_hint(
    runner: &CairoRunner,
    hint_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let wasm_bytes = wat2wasm(hint_bytes)?;
    let store = Store::default();
    //Compile module
    let module = Module::new(&store, wasm_bytes)?;

    //Shared values
    let shared_ap = Arc::new(Mutex::new(runner.vm.run_context.ap.clone()));

    #[derive(WasmerEnv, Clone)]
    struct Env {
        memory: Arc<Mutex<Memory>>,
        segments: Arc<Mutex<MemorySegmentManager>>,
        ap: Arc<Mutex<MaybeRelocatable>>,
    }

    //Function imported by hint
    fn add_segment(env: &Env) {
        let mut segments = env.segments.lock().unwrap();
        let mut memory = env.memory.lock().unwrap();
        let ap = env.ap.lock().unwrap();
        let rel = segments.add(&mut (*memory), None);
        (*memory)
            .insert(&*ap, &MaybeRelocatable::RelocatableValue(rel))
            .unwrap();
    }

    // Create an import object.
    let import_object = imports! {
        "env" => {
            "add_segment" => Function::new_native_with_env(&store, Env { memory: runner.vm.memory.clone(), segments: runner.vm.segments.clone(), ap: shared_ap.clone() }, add_segment),
            //Env Received by function must be static
        }
    };
    let instance = Instance::new(&module, &import_object)?;
    let hint = instance.exports.get_function("hint")?;
    hint.call(&[])?;

    Ok(())
}

/*
Block of wasm code to execute alloc() hint:
            br#"
    (module
        (func $add_segment (import "env" "add_segment"))
        (func $function (export "hint") call $add_segment))
    "#
*/

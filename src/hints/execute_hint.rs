use crate::types::relocatable::MaybeRelocatable;
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use std::sync::{Arc, Mutex};
use wasmer::{imports, wat2wasm, Function, Instance, Module, Store, WasmerEnv};

pub fn execute_hint(
    vm: &VirtualMachine,
    hint_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let wasm_bytes = wat2wasm(hint_bytes)?;
    let store = Store::default();
    //Compile module
    let module = Module::new(&store, wasm_bytes)?;

    //Shared values
    let shared_ap = Arc::new(Mutex::new(vm.run_context.ap.clone()));

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
            "add_segment" => Function::new_native_with_env(&store, Env { memory: vm.memory.clone(), segments: vm.segments.clone(), ap: shared_ap }, add_segment),
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

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, Sign};

    use super::*;
    #[test]
    fn run_alloc_hint_empty_memory() {
        let wasm_bytes = br#"
        (module
            (func $add_segment (import "env" "add_segment"))
            (func $function (export "hint") call $add_segment))
        "#;
        let vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        execute_hint(&vm, wasm_bytes).expect("Error while executing hint");
        //first new segment is added
        assert_eq!(vm.segments.lock().unwrap().num_segments, 1);
        //new segment base (0,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory
                .lock()
                .unwrap()
                .get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((0, 0))))
        );
    }

    #[test]
    fn run_alloc_hint_preset_memory() {
        let wasm_bytes = br#"
        (module
            (func $add_segment (import "env" "add_segment"))
            (func $function (export "hint") call $add_segment))
        "#;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments
                .lock()
                .unwrap()
                .add(&mut vm.memory.lock().unwrap(), None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        execute_hint(&vm, wasm_bytes).expect("Error while executing hint");
        //Segment N°4 is added
        assert_eq!(vm.segments.lock().unwrap().num_segments, 4);
        //new segment base (3,0) is inserted into ap (2,6)
        assert_eq!(
            vm.memory
                .lock()
                .unwrap()
                .get(&MaybeRelocatable::from((2, 6))),
            Ok(Some(&MaybeRelocatable::from((3, 0))))
        );
    }
}

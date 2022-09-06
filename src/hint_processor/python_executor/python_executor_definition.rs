use std::{any::Any, collections::HashMap, io::Write, os::unix::net::UnixStream};

use serde::Serialize;

use crate::{
    hint_processor::python_compatible_helpers::get_python_compatible_memory,
    types::relocatable::MaybeRelocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

#[derive(Serialize)]
pub struct PythonData {
    memory: HashMap<(usize, usize), MaybeRelocatable>,
    num_segments: usize,
    ap: (usize, usize),
    fp: (usize, usize),
    pc: (usize, usize),
}
pub struct PythonExecutor {}

impl PythonExecutor {
    pub fn execute_hint(
        vm: &mut VirtualMachine,
        _hint_data: &Box<dyn Any>,
    ) -> Result<(), VirtualMachineError> {
        let memory = get_python_compatible_memory(&vm.memory);
        let python_data = PythonData {
            memory,
            num_segments: vm.segments.num_segments,
            ap: (1, vm.run_context.ap),
            fp: (1, vm.run_context.fp),
            pc: (vm.run_context.pc.segment_index, vm.run_context.pc.offset),
        };
        let mut stream = UnixStream::connect("ipc.sock").map_err(|_| {
            VirtualMachineError::PythonHint("Failed to establish connection".to_string())
        })?;
        //let serialized_memory = serde_json::to_string(&memory).map_err(|_|VirtualMachineError::PythonHint("Failed to serielize memory".to_string()))?;
        let serialized_memory = serde_json::to_string(&python_data).unwrap();
        stream
            .write_all(serialized_memory.as_bytes())
            .map_err(|_| {
                VirtualMachineError::PythonHint(
                    "Failed to communicate with python process".to_string(),
                )
            })?;
        Ok(())
    }
}

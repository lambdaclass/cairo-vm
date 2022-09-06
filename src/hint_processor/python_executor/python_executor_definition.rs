use std::{any::Any, io::Write, os::unix::net::UnixStream};

use serde::Serialize;

use crate::{
    hint_processor::{
        builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData,
        python_compatible_helpers::get_python_compatible_memory,
    },
    types::relocatable::MaybeRelocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

#[derive(Serialize)]
pub struct PythonData {
    code: String,
    memory: Vec<((usize, usize), MaybeRelocatable)>,
    num_segments: usize,
    ap: (usize, usize),
    fp: (usize, usize),
    pc: (usize, usize),
}
pub struct PythonExecutor {}

impl PythonExecutor {
    pub fn execute_hint(
        vm: &mut VirtualMachine,
        hint_data: &Box<dyn Any>,
    ) -> Result<(), VirtualMachineError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;

        let memory = get_python_compatible_memory(&vm.memory);
        let python_data = PythonData {
            code: hint_data.code.clone(),
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

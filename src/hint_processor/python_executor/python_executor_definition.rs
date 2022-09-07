use std::{
    any::Any,
    io::{Read, Write},
    net::TcpStream,
};

use serde::Serialize;

use crate::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

#[derive(Serialize)]
pub struct PythonData {
    code: String,
    ap: (usize, usize),
    fp: (usize, usize),
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

        let mut stream = TcpStream::connect(("localhost", 60000)).map_err(|_| {
            VirtualMachineError::PythonHint("Failed to establish connection".to_string())
        })?;
        let python_data = PythonData {
            code: hint_data.code.clone(),
            ap: (1, vm.run_context.ap),
            fp: (1, vm.run_context.fp),
        };
        let serialized_data = serde_json::to_string(&python_data)
            .map_err(|_| VirtualMachineError::PythonHint("Failed to serielize data".to_string()))?;
        stream.write(serialized_data.as_bytes()).unwrap();
        let mut finished_hint = false;
        let mut counter = 3;
        while !finished_hint && counter != 0 {
            let mut response = [0; 1024];
            stream.read(&mut response).unwrap();
            println!(
                "Response: {:?}",
                std::str::from_utf8(&response)
                    .unwrap()
                    .trim_end_matches('\0')
            );
            match std::str::from_utf8(&response)
                .unwrap()
                .trim_end_matches('\0')
            {
                "Ok" => finished_hint = true,
                "ADD_SEGMENT" => {
                    println!("Adding a Segment");
                    let base = vm.segments.add(&mut vm.memory);
                    println!("SENDING: {:?}", &(base.segment_index, base.offset));
                    stream
                        .write(
                            serde_json::to_string(&(base.segment_index, base.offset))
                                .unwrap()
                                .as_bytes(),
                        )
                        .unwrap();
                    //stream.shutdown(Shutdown::Both).unwrap();
                    println!("Response sent back to python")
                }
                _ => (),
            }
            counter -= 1;
        }
        Ok(())
    }
}

use std::{
    any::Any,
    io::{Read, Write},
    net::TcpStream,
};

use crate::{
    bigint,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData,
    types::relocatable::Relocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct PythonData {
    code: String,
    ap: (usize, usize),
    fp: (usize, usize),
}

#[derive(Serialize, Deserialize)]
pub struct PythonOperation<'a> {
    operation: &'a str,
    args: Option<&'a str>,
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
        //Establish connection
        let mut stream = TcpStream::connect(("localhost", 60000)).map_err(|_| {
            VirtualMachineError::PythonHint("Failed to establish connection".to_string())
        })?;
        //Send initial python data
        let python_data = PythonData {
            code: hint_data.code.clone(),
            ap: (1, vm.run_context.ap),
            fp: (1, vm.run_context.fp),
        };
        let serialized_data = serde_json::to_string(&python_data)
            .map_err(|_| VirtualMachineError::PythonHint("Failed to serielize data".to_string()))?;
        stream.write_all(serialized_data.as_bytes()).unwrap();
        //Start operation loop
        let mut finished_hint = false;
        let mut counter = 3; //Counter is a temporary measure to prevent infinite looping
        while !finished_hint && counter != 0 {
            //Read requests from python process
            let mut response = [0; 1024];
            stream.read(&mut response).unwrap();
            let json_data = std::str::from_utf8(&response)
                .unwrap()
                .trim_end_matches('\0');
            let python_operation: PythonOperation = serde_json::from_str(json_data).unwrap();
            //Execute operations
            match python_operation.operation {
                "Ok" => finished_hint = true,
                "ADD_SEGMENT" => {
                    let base = vm.segments.add(&mut vm.memory);
                    stream
                        .write_all(
                            serde_json::to_string(&(base.segment_index, base.offset))
                                .unwrap()
                                .as_bytes(),
                        )
                        .unwrap();
                }
                "MEMORY_INSERT" => {
                    //Yes this code is ugly
                    //Fix to accept BigInt too
                    //Parse arguments & carry out operation
                    let parse_result: Result<((usize, usize), usize), _> =
                        serde_json::from_str(python_operation.args.unwrap());
                    match parse_result {
                        Err(_) => {
                            let parse_result: Result<((usize, usize), (usize, usize)), _> =
                                serde_json::from_str(python_operation.args.unwrap());
                            let parse_result = parse_result.expect("Failed argument parse");
                            vm.memory.insert(
                                &(Relocatable::from(parse_result.0)),
                                &(Relocatable::from(parse_result.1)),
                            )?;
                        }
                        Ok(parse_result) => {
                            vm.memory.insert(
                                &(Relocatable::from(parse_result.0)),
                                &bigint!(parse_result.1),
                            )?;
                        }
                    }
                    //Inform that the operation was succesful
                    stream.write_all(b"Ok").unwrap();
                }
                _ => (),
            }
            counter -= 1;
        }
        //TODO: Apply final changes : aka check run_context, ids, etc
        Ok(())
    }
}

use std::{
    any::Any,
    collections::HashMap,
    fmt,
    io::{Read, Write},
    net::TcpStream,
};

use crate::{
    bigint,
    hint_processor::{
        builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData,
        hint_processor_definition::HintReference,
        python_compatible_helpers::{compute_addr_from_reference, get_python_compatible_ids},
    },
    serde::deserialize_program::ApTracking,
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::vm_errors::VirtualMachineError,
        vm_core::VirtualMachine,
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
};
use num_bigint::BigInt;
use serde::Deserializer;
use serde::{
    de::{self, MapAccess},
    Deserialize, Serialize,
};

#[derive(Deserialize, Debug)]
pub struct PythonUpdate {
    #[serde(deserialize_with = "deserialize_py_ids")]
    ids: HashMap<String, MaybeRelocatable>,
    ap: usize,
    fp: usize,
}

#[derive(Serialize, Debug)]
pub struct PythonData {
    code: String,
    ap: usize,
    fp: usize,
    ids: HashMap<String, Option<MaybeRelocatable>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PythonOperation<'a> {
    operation: &'a str,
    args: Option<String>,
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
        let serialized_data = get_serialized_python_data(hint_data, vm)?;
        stream.write_all(serialized_data.as_bytes()).unwrap();
        //Process operations
        process_python_operations(vm, &mut stream, hint_data)?;
        Ok(())
    }
}

pub fn process_python_operations(
    vm: &mut VirtualMachine,
    stream: &mut TcpStream,
    hint_data: &HintProcessorData,
) -> Result<(), VirtualMachineError> {
    let mut finished_hint = false;
    let mut counter = 10; //Counter is a temporary measure to prevent infinite looping
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
            "ADD_SEGMENT" => process_add_segment(stream, &mut vm.memory, &mut vm.segments)?,
            "MEMORY_INSERT" => {
                if python_operation.args.is_none() {
                    return Err(VirtualMachineError::PythonHint(
                        "No args received for MEMORY_INSERT".to_string(),
                    ));
                };
                process_memory_insert(stream, &python_operation.args.unwrap(), &mut vm.memory)?;
            }
            "MEMORY_GET" => {
                if python_operation.args.is_none() {
                    return Err(VirtualMachineError::PythonHint(
                        "No args received for MEMORY_GET".to_string(),
                    ));
                };
                let args = python_operation.args.unwrap();
                process_memory_get(stream, &args, &mut vm.memory)?;
            }
            "UPDATE_DATA" => {
                if python_operation.args.is_none() {
                    return Err(VirtualMachineError::PythonHint(
                        "No args received for UPDATE_DATA".to_string(),
                    ));
                };
                process_update_data(stream, &python_operation.args.unwrap(), vm, hint_data)?;
            }
            _ => (),
        }
        counter -= 1;
    }
    Ok(())
}

pub fn process_update_data(
    stream: &mut TcpStream,
    args: &str,
    vm: &mut VirtualMachine,
    hint_data: &HintProcessorData,
) -> Result<(), VirtualMachineError> {
    let update_data: PythonUpdate = serde_json::from_str(args).unwrap();
    //Perform update
    vm.run_context.ap = update_data.ap;
    vm.run_context.fp = update_data.fp;
    update_ids(
        vm,
        &hint_data.ids_data,
        &hint_data.ap_tracking,
        &update_data.ids,
    )?;
    //Inform that the operation was succesful
    stream.write_all(b"Ok").unwrap();
    Ok(())
}

pub fn process_add_segment(
    stream: &mut TcpStream,
    memory: &mut Memory,
    segments: &mut MemorySegmentManager,
) -> Result<(), VirtualMachineError> {
    let base = segments.add(memory);
    stream
        .write_all(
            serde_json::to_string(&(base.segment_index, base.offset))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    Ok(())
}

pub fn process_memory_insert(
    stream: &mut TcpStream,
    args: &str,
    memory: &mut Memory,
) -> Result<(), VirtualMachineError> {
    //TODO: Improve parsing
    //TODO Fix to accept BigInt too
    //Parse arguments & carry out operation
    let parse_result: Result<((usize, usize), usize), _> = serde_json::from_str(args);
    match parse_result {
        Err(_) => {
            let parse_result: Result<((usize, usize), (usize, usize)), _> =
                serde_json::from_str(args);
            let parse_result = parse_result.expect("Failed argument parse");
            memory.insert(
                &(Relocatable::from(parse_result.0)),
                &(Relocatable::from(parse_result.1)),
            )?;
        }
        Ok(parse_result) => {
            memory.insert(
                &(Relocatable::from(parse_result.0)),
                &bigint!(parse_result.1),
            )?;
        }
    }
    //Inform that the operation was succesful
    stream.write_all(b"Ok").unwrap();
    Ok(())
}

pub fn process_memory_get(
    stream: &mut TcpStream,
    args: &str,
    memory: &mut Memory,
) -> Result<(), VirtualMachineError> {
    //Parse arguments & carry out operation
    let parse_result: (usize, usize) = serde_json::from_str(args).map_err(|_| {
        VirtualMachineError::PythonHint("Failed to parse arguments for MEMORY_GET".to_string())
    })?;
    let value =
        memory
            .get(&Relocatable::from(parse_result))?
            .ok_or(VirtualMachineError::MemoryGet(MaybeRelocatable::from(
                parse_result,
            )))?;
    //Send back the result of the operation
    stream
        .write_all(serde_json::to_string(&value).unwrap().as_bytes())
        .unwrap();
    Ok(())
}

pub fn get_serialized_python_data(
    hint_data: &HintProcessorData,
    vm: &VirtualMachine,
) -> Result<String, VirtualMachineError> {
    let ids = get_python_compatible_ids(vm, &hint_data.ids_data, &hint_data.ap_tracking)?;
    let python_data = PythonData {
        code: hint_data.code.clone(),
        ap: vm.run_context.ap,
        fp: vm.run_context.fp,
        ids,
    };
    serde_json::to_string(&python_data)
        .map_err(|_| VirtualMachineError::PythonHint("Failed to serialize data".to_string()))
}

pub fn update_ids(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    update_data: &HashMap<String, MaybeRelocatable>,
) -> Result<(), VirtualMachineError> {
    for (name, value) in update_data.iter() {
        let addr = compute_addr_from_reference(
            ids_data.get(name).unwrap(),
            &vm.run_context,
            &vm.memory,
            ap_tracking,
        )?;
        vm.memory.insert(&addr, value)?;
    }
    Ok(())
}

pub fn deserialize_py_ids<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<HashMap<String, MaybeRelocatable>, D::Error> {
    d.deserialize_map(MaybeRelocatableVisitor)
}
struct MaybeRelocatableVisitor;

impl<'de> de::Visitor<'de> for MaybeRelocatableVisitor {
    type Value = HashMap<String, MaybeRelocatable>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Could not deserialize ids")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut data: HashMap<String, MaybeRelocatable> = HashMap::new();
        let mut reading = true;
        while reading {
            reading = false;
            while let Some((name, val)) = map.next_entry::<String, usize>()? {
                data.insert(name, MaybeRelocatable::from(bigint!(val)));
                reading = true;
            }
            while let Some((name, val)) = map.next_entry::<String, (usize, usize)>()? {
                data.insert(name, MaybeRelocatable::from(val));
                reading = true;
            }
        }
        Ok(data)
    }
}

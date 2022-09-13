use std::{any::Any, collections::HashMap, thread};

use crate::{
    bigint,
    hint_processor::{
        builtin_hint_processor::python_executor_helpers::get_value_from_reference,
        hint_processor_definition::HintReference, hint_processor_utils::bigint_to_usize,
    },
    pycell,
    serde::deserialize_program::ApTracking,
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use super::{
    builtin_hint_processor_definition::HintProcessorData,
    python_executor_helpers::{compute_addr_from_reference, write_py_vec_args},
};
use crossbeam_channel::{unbounded, Receiver, Sender};
use num_bigint::BigInt;
use pyo3::{exceptions::PyTypeError, prelude::*, py_run};

const CHANNEL_ERROR_MSG: &str = "Failed to communicate between channels";

#[derive(FromPyObject, Debug)]
pub enum PyMaybeRelocatable {
    Int(BigInt),
    RelocatableValue(PyRelocatable),
}

impl From<MaybeRelocatable> for PyMaybeRelocatable {
    fn from(val: MaybeRelocatable) -> Self {
        match val {
            MaybeRelocatable::RelocatableValue(rel) => PyMaybeRelocatable::RelocatableValue(
                PyRelocatable::new((rel.segment_index, rel.offset)),
            ),
            MaybeRelocatable::Int(num) => PyMaybeRelocatable::Int(num),
        }
    }
}

impl From<&MaybeRelocatable> for PyMaybeRelocatable {
    fn from(val: &MaybeRelocatable) -> Self {
        match val {
            MaybeRelocatable::RelocatableValue(rel) => PyMaybeRelocatable::RelocatableValue(
                PyRelocatable::new((rel.segment_index, rel.offset)),
            ),
            MaybeRelocatable::Int(num) => PyMaybeRelocatable::Int(num.clone()),
        }
    }
}

impl From<PyMaybeRelocatable> for MaybeRelocatable {
    fn from(val: PyMaybeRelocatable) -> Self {
        match val {
            PyMaybeRelocatable::RelocatableValue(rel) => {
                MaybeRelocatable::RelocatableValue(Relocatable::from((rel.index, rel.offset)))
            }
            PyMaybeRelocatable::Int(num) => MaybeRelocatable::Int(num),
        }
    }
}

impl From<&PyMaybeRelocatable> for MaybeRelocatable {
    fn from(val: &PyMaybeRelocatable) -> Self {
        match val {
            PyMaybeRelocatable::RelocatableValue(rel) => {
                MaybeRelocatable::RelocatableValue(Relocatable::from((rel.index, rel.offset)))
            }
            PyMaybeRelocatable::Int(num) => MaybeRelocatable::Int(num.clone()),
        }
    }
}

impl From<Relocatable> for PyRelocatable {
    fn from(val: Relocatable) -> Self {
        PyRelocatable::new((val.segment_index, val.offset))
    }
}

#[pyclass(name = "Relocatable")]
#[derive(Clone, Debug)]
pub struct PyRelocatable {
    index: usize,
    offset: usize,
}

#[pymethods]
impl PyRelocatable {
    #[new]
    pub fn new(tuple: (usize, usize)) -> PyRelocatable {
        PyRelocatable {
            index: tuple.0,
            offset: tuple.1,
        }
    }

    pub fn __add__(&self, value: usize) -> PyRelocatable {
        PyRelocatable {
            index: self.index,
            offset: self.offset + value,
        }
    }

    pub fn __sub__(&self, value: PyMaybeRelocatable, py: Python) -> PyResult<PyObject> {
        match value {
            PyMaybeRelocatable::Int(value) => {
                let result = bigint_to_usize(&value);
                if let Ok(value) = result {
                    if value <= self.offset {
                        return Ok(PyMaybeRelocatable::RelocatableValue(PyRelocatable {
                            index: self.index,
                            offset: self.offset - value,
                        })
                        .to_object(py));
                    };
                }
                Err(PyTypeError::new_err(
                    "MaybeRelocatable substraction failure: Offset exceeded",
                ))
            }
            PyMaybeRelocatable::RelocatableValue(address) => {
                if self.index == address.index && self.offset >= address.offset {
                    return Ok(
                        PyMaybeRelocatable::Int(bigint!(self.offset - address.offset))
                            .to_object(py),
                    );
                }
                Err(PyTypeError::new_err(
                    "Cant sub two Relocatables of different segments",
                ))
            }
        }
    }

    pub fn __repr__(&self) -> String {
        format!("({}, {})", self.index, self.offset)
    }
}

impl PyRelocatable {
    pub fn to_relocatable(&self) -> Relocatable {
        Relocatable {
            segment_index: self.index,
            offset: self.offset,
        }
    }
}

impl ToPyObject for PyMaybeRelocatable {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        match self {
            PyMaybeRelocatable::RelocatableValue(address) => address.clone().into_py(py),
            PyMaybeRelocatable::Int(value) => value.clone().into_py(py),
        }
    }
}

#[derive(Debug)]
pub enum Operation {
    AddSegment,
    WriteMemory(PyRelocatable, PyMaybeRelocatable),
    ReadMemory(PyRelocatable),
    ReadIds(String),
    WriteIds(String, PyMaybeRelocatable),
    WriteVecArg(PyRelocatable, Vec<PyMaybeRelocatable>),
    End,
}

#[derive(Debug)]
pub enum OperationResult {
    Reading(PyMaybeRelocatable),
    Segment(PyRelocatable),
    Success,
}

#[pyclass]
pub struct PySegmentManager {
    operation_sender: Sender<Operation>,
    result_receiver: Receiver<OperationResult>,
}

#[pymethods]
impl PySegmentManager {
    pub fn add(&self) -> PyResult<PyRelocatable> {
        self.operation_sender
            .send(Operation::AddSegment)
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?;
        if let OperationResult::Segment(result) = self
            .result_receiver
            .recv()
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?
        {
            return Ok(result);
        }
        Err(PyTypeError::new_err("segments.add() failure"))
    }

    pub fn write_arg(&self, ptr: PyRelocatable, arg: Vec<PyMaybeRelocatable>) -> PyResult<()> {
        self.operation_sender
            .send(Operation::WriteVecArg(ptr, arg))
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?;
        if let OperationResult::Success = self
            .result_receiver
            .recv()
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?
        {
            return Ok(());
        }
        Err(PyTypeError::new_err("segments.write_arg() failure"))
    }
}

impl PySegmentManager {
    pub fn new(
        operation_sender: Sender<Operation>,
        result_receiver: Receiver<OperationResult>,
    ) -> PySegmentManager {
        PySegmentManager {
            operation_sender,
            result_receiver,
        }
    }
}

#[pyclass]
pub struct PyMemory {
    operation_sender: Sender<Operation>,
    result_receiver: Receiver<OperationResult>,
}

#[pymethods]
impl PyMemory {
    pub fn __getitem__(&self, key: &PyRelocatable, py: Python) -> PyResult<PyObject> {
        self.operation_sender
            .send(Operation::ReadMemory(PyRelocatable::new((
                key.index, key.offset,
            ))))
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?;
        if let OperationResult::Reading(result) = self
            .result_receiver
            .recv()
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?
        {
            return Ok(result.to_object(py));
        }
        Err(PyTypeError::new_err("memory.__getitem__ failure"))
    }

    pub fn __setitem__(&self, key: &PyRelocatable, value: PyMaybeRelocatable) -> PyResult<()> {
        self.operation_sender
            .send(Operation::WriteMemory(
                PyRelocatable::new((key.index, key.offset)),
                value,
            ))
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?;
        if let OperationResult::Success = self
            .result_receiver
            .recv()
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?
        {
            return Ok(());
        }
        Err(PyTypeError::new_err("memory.__setitem__() failure"))
    }
}

impl PyMemory {
    pub fn new(
        operation_sender: Sender<Operation>,
        result_receiver: Receiver<OperationResult>,
    ) -> PyMemory {
        PyMemory {
            operation_sender,
            result_receiver,
        }
    }
}

#[pyclass]
pub struct PyIds {
    operation_sender: Sender<Operation>,
    result_receiver: Receiver<OperationResult>,
}

#[pymethods]
impl PyIds {
    pub fn __getattr__(&self, name: &str, py: Python) -> PyResult<PyObject> {
        self.operation_sender
            .send(Operation::ReadIds(name.to_string()))
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?;
        if let OperationResult::Reading(result) = self
            .result_receiver
            .recv()
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?
        {
            return Ok(result.to_object(py));
        }
        Err(PyTypeError::new_err("ids.__getattr__() failure"))
    }

    pub fn __setattr__(&self, name: &str, value: PyMaybeRelocatable) -> PyResult<()> {
        self.operation_sender
            .send(Operation::WriteIds(name.to_string(), value))
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?;
        if let OperationResult::Success = self
            .result_receiver
            .recv()
            .map_err(|_| PyTypeError::new_err(CHANNEL_ERROR_MSG))?
        {
            return Ok(());
        }
        Err(PyTypeError::new_err("ids.__setattr__() failure"))
    }
}

impl PyIds {
    pub fn new(
        operation_sender: Sender<Operation>,
        result_receiver: Receiver<OperationResult>,
    ) -> PyIds {
        PyIds {
            operation_sender,
            result_receiver,
        }
    }
}

fn handle_messages(
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    operation_receiver: Receiver<Operation>,
    result_sender: Sender<OperationResult>,
    vm: &mut VirtualMachine,
) -> Result<(), VirtualMachineError> {
    loop {
        match operation_receiver
            .recv()
            .map_err(|_| VirtualMachineError::PythonExecutorChannel)?
        {
            Operation::End => break,
            Operation::ReadMemory(address) => {
                if let Some(value) = vm.memory.get(&address.to_relocatable())? {
                    send_message(&result_sender, OperationResult::Reading(value.into()))?;
                };
            }
            Operation::WriteMemory(key, value) => {
                vm.memory.insert(
                    &key.to_relocatable(),
                    &(Into::<MaybeRelocatable>::into(value)),
                )?;
                send_message(&result_sender, OperationResult::Success)?;
            }
            Operation::AddSegment => {
                let result = vm.segments.add(&mut vm.memory);
                send_message(&result_sender, OperationResult::Segment(result.into()))?;
            }
            Operation::ReadIds(name) => {
                let hint_ref = ids_data
                    .get(&name)
                    .ok_or(VirtualMachineError::FailedToGetIds)?;
                let value = get_value_from_reference(vm, hint_ref, ap_tracking)?;
                send_message(&result_sender, OperationResult::Reading(value.into()))?;
            }
            Operation::WriteIds(name, value) => {
                let hint_ref = ids_data
                    .get(&name)
                    .ok_or(VirtualMachineError::FailedToGetIds)?;
                let addr = compute_addr_from_reference(
                    hint_ref,
                    &vm.run_context,
                    &vm.memory,
                    ap_tracking,
                )?;
                vm.memory
                    .insert(&addr, &(Into::<MaybeRelocatable>::into(value)))?;
                send_message(&result_sender, OperationResult::Success)?;
            }
            Operation::WriteVecArg(ptr, arg) => {
                write_py_vec_args(&mut vm.memory, &ptr, &arg, &vm.prime)?;
                send_message(&result_sender, OperationResult::Success)?;
            }
        }
    }
    Ok(())
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
        let code = hint_data.code.clone();

        let (operation_sender, operation_receiver) = unbounded();
        let (result_sender, result_receiver) = unbounded();
        let ap = vm.run_context.ap;
        let fp = vm.run_context.fp;
        pyo3::prepare_freethreaded_python();
        let gil = Python::acquire_gil();
        let py = gil.python();
        py.allow_threads(move || -> Result<(), VirtualMachineError> {
            thread::spawn(move || -> Result<(), VirtualMachineError> {
                println!(" -- Starting python hint execution -- ");
                let gil = Python::acquire_gil();
                let py = gil.python();
                let memory = pycell!(
                    py,
                    PyMemory::new(operation_sender.clone(), result_receiver.clone())
                );
                let segments = pycell!(
                    py,
                    PySegmentManager::new(operation_sender.clone(), result_receiver.clone())
                );
                let ids = pycell!(py, PyIds::new(operation_sender.clone(), result_receiver));
                let ap = pycell!(py, PyRelocatable::new((1, ap)));
                let fp = pycell!(py, PyRelocatable::new((1, fp)));
                py_run!(py, memory segments ap fp ids, &code);
                println!(" -- Ending python hint -- ");
                operation_sender
                    .send(Operation::End)
                    .map_err(|_| VirtualMachineError::PythonExecutorChannel)?;
                Ok(())
            });
            handle_messages(
                &hint_data.ids_data,
                &hint_data.ap_tracking,
                operation_receiver,
                result_sender,
                vm,
            )
        })?;
        Ok(())
    }
}

fn send_message(
    sender: &Sender<OperationResult>,
    message: OperationResult,
) -> Result<(), VirtualMachineError> {
    sender
        .send(message)
        .map_err(|_| VirtualMachineError::PythonExecutorChannel)
}

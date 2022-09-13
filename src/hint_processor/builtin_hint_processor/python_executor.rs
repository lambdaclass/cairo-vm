use std::{
    any::Any,
    collections::HashMap,
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use crate::{
    bigint,
    hint_processor::{
        builtin_hint_processor::python_executor_helpers::get_value_from_reference,
        hint_processor_definition::HintReference, hint_processor_utils::bigint_to_usize,
    },
    serde::deserialize_program::ApTracking,
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use super::{
    builtin_hint_processor_definition::HintProcessorData,
    python_executor_helpers::compute_addr_from_reference,
};
use num_bigint::BigInt;
use pyo3::{prelude::*, py_run};

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
                Ok(PyMaybeRelocatable::RelocatableValue(PyRelocatable {
                    index: self.index,
                    offset: self.offset - bigint_to_usize(&value).unwrap(),
                })
                .to_object(py))
            }
            PyMaybeRelocatable::RelocatableValue(address) => {
                if self.index == address.index && self.offset >= address.offset {
                    return Ok(
                        PyMaybeRelocatable::Int(bigint!(self.offset - address.offset))
                            .to_object(py),
                    );
                }
                todo!()
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
        self.operation_sender.send(Operation::AddSegment).unwrap();
        if let OperationResult::Segment(result) = self.result_receiver.recv().unwrap() {
            return Ok(result);
        }
        todo!()
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
            .unwrap();
        if let OperationResult::Reading(result) = self.result_receiver.recv().unwrap() {
            return Ok(result.to_object(py));
        }
        todo!()
    }

    pub fn __setitem__(&self, key: &PyRelocatable, value: PyMaybeRelocatable) -> PyResult<()> {
        self.operation_sender
            .send(Operation::WriteMemory(
                PyRelocatable::new((key.index, key.offset)),
                value,
            ))
            .unwrap();
        self.result_receiver.recv().unwrap();
        Ok(())
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
    _operation_sender: Sender<Operation>,
    _result_receiver: Receiver<OperationResult>,
}
impl PyIds {
    pub fn new(
        _operation_sender: Sender<Operation>,
        _result_receiver: Receiver<OperationResult>,
    ) -> PyIds {
        PyIds {
            _operation_sender,
            _result_receiver,
        }
    }
}

fn handle_memory_messages(
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    operation_receiver: Receiver<Operation>,
    result_sender: Sender<OperationResult>,
    segment_result_sender: Sender<OperationResult>,
    ids_result_sender: Sender<OperationResult>,
    vm: &mut VirtualMachine,
) {
    loop {
        match operation_receiver.recv().unwrap() {
            Operation::End => break,
            Operation::ReadMemory(address) => {
                if let Some(value) = vm.memory.get(&address.to_relocatable()).unwrap() {
                    result_sender
                        .send(OperationResult::Reading(Into::<PyMaybeRelocatable>::into(
                            value,
                        )))
                        .unwrap();
                };
            }
            Operation::WriteMemory(key, value) => {
                vm.memory
                    .insert(
                        &key.to_relocatable(),
                        &(Into::<MaybeRelocatable>::into(value)),
                    )
                    .unwrap();
                result_sender.send(OperationResult::Success).unwrap();
            }
            Operation::AddSegment => {
                let result = vm.segments.add(&mut vm.memory);
                segment_result_sender
                    .send(OperationResult::Segment(PyRelocatable::new((
                        result.segment_index,
                        result.offset,
                    ))))
                    .unwrap()
            }
            Operation::ReadIds(name) => {
                let hint_ref = ids_data.get(&name).unwrap();
                let value = get_value_from_reference(vm, hint_ref, ap_tracking)
                    .unwrap()
                    .unwrap();
                ids_result_sender
                    .send(OperationResult::Reading(value.into()))
                    .unwrap();
            }
            Operation::WriteIds(name, value) => {
                let hint_ref = ids_data.get(&name).unwrap();
                let addr = compute_addr_from_reference(
                    hint_ref,
                    &vm.run_context,
                    &vm.memory,
                    &ap_tracking,
                )
                .unwrap();
                vm.memory
                    .insert(&addr, &(Into::<MaybeRelocatable>::into(value)))
                    .unwrap();
                ids_result_sender.send(OperationResult::Success).unwrap()
            }
        }
    }
}

pub struct PythonExecutor {}

impl PythonExecutor {
    pub fn execute_hint(
        mut vm: &mut VirtualMachine,
        hint_data: &Box<dyn Any>,
    ) -> Result<(), VirtualMachineError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;
        let code = hint_data.code.clone();

        let (operation_sender, operation_receiver) = mpsc::channel();
        let (result_sender, result_receiver) = mpsc::channel::<OperationResult>();
        let (segment_result_sender, segment_result_receiver) = mpsc::channel::<OperationResult>();
        let (ids_result_sender, ids_result_receiver) = mpsc::channel::<OperationResult>();
        let ap = vm.run_context.ap;
        let fp = vm.run_context.fp;
        let gil = Python::acquire_gil();
        let py = gil.python();
        py.allow_threads(move || {
            thread::spawn(move || {
                println!(" -- Starting python hint execution -- ");
                let gil = Python::acquire_gil();
                let py = gil.python();
                let memory =
                    PyCell::new(py, PyMemory::new(operation_sender.clone(), result_receiver))
                        .unwrap();
                let segments = PyCell::new(
                    py,
                    PySegmentManager::new(operation_sender.clone(), segment_result_receiver),
                )
                .unwrap();
                let ids = PyCell::new(
                    py,
                    PyIds::new(operation_sender.clone(), ids_result_receiver),
                )
                .unwrap();
                let ap = PyCell::new(py, PyRelocatable::new((1, ap))).unwrap();
                let fp = PyCell::new(py, PyRelocatable::new((1, fp))).unwrap();
                py_run!(py, memory segments ap fp ids, &code);
                println!(" -- Ending python hint -- ");
                operation_sender.send(Operation::End).unwrap();
            });
            handle_memory_messages(
                &hint_data.ids_data,
                &hint_data.ap_tracking,
                operation_receiver,
                result_sender,
                segment_result_sender,
                ids_result_sender,
                &mut vm,
            );
        });
        Ok(())
    }
}

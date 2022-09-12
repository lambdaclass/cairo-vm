use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
};

use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
};
use num_bigint::BigInt;
use pyo3::{prelude::*, py_run};

#[pyclass]
pub struct PyMemory {
    operation_sender: Sender<MemoryOperation>,
    result_receiver: Receiver<MemoryResult>,
}

#[derive(FromPyObject, Debug)]
pub enum PyMaybeRelocatable {
    Int(BigInt),
    RelocatableValue((usize, usize)),
}

impl ToPyObject for PyMaybeRelocatable {
    fn to_object(&self, py: Python<'_>) -> PyObject {
        match self {
            PyMaybeRelocatable::RelocatableValue(address) => address.into_py(py),
            PyMaybeRelocatable::Int(value) => value.clone().into_py(py),
        }
    }
}

#[pymethods]
impl PyMemory {
    pub fn add_segment(&self) -> PyResult<(usize, usize)> {
        self.operation_sender
            .send(MemoryOperation::AddSegment)
            .unwrap();
        if let MemoryResult::Segment(result) = self.result_receiver.recv().unwrap() {
            return Ok(result);
        }
        todo!()
    }

    pub fn __getitem__(&self, key: (usize, usize), py: Python) -> PyResult<PyObject> {
        self.operation_sender
            .send(MemoryOperation::ReadMemory(key))
            .unwrap();
        if let MemoryResult::Reading(result) = self.result_receiver.recv().unwrap() {
            return Ok(result.to_object(py));
        }
        todo!()
    }

    pub fn __setitem__(&self, key: (usize, usize), value: PyMaybeRelocatable) -> PyResult<()> {
        self.operation_sender
            .send(MemoryOperation::WriteMemory(key, value))
            .unwrap();
        self.result_receiver.recv().unwrap();
        Ok(())
    }
}

impl PyMemory {
    pub fn new(
        operation_sender: Sender<MemoryOperation>,
        result_receiver: Receiver<MemoryResult>,
    ) -> PyMemory {
        PyMemory {
            operation_sender,
            result_receiver,
        }
    }
}

#[derive(Debug)]
pub enum MemoryOperation {
    AddSegment,
    WriteMemory((usize, usize), PyMaybeRelocatable),
    ReadMemory((usize, usize)),
    End,
}

#[derive(Debug)]
pub enum MemoryResult {
    Reading(PyMaybeRelocatable),
    Segment((usize, usize)),
    Success,
}

fn handle_memory_messages(
    operation_receiver: Receiver<MemoryOperation>,
    result_sender: Sender<MemoryResult>,
    memory: &mut Memory,
    segments: &mut MemorySegmentManager,
) {
    loop {
        match operation_receiver.recv().unwrap() {
            MemoryOperation::End => break,
            MemoryOperation::ReadMemory(address) => {
                if let Some(value) = memory.get(&Relocatable::from(address)).unwrap() {
                    match value {
                        MaybeRelocatable::Int(value) => result_sender
                            .send(MemoryResult::Reading(PyMaybeRelocatable::Int(
                                value.clone(),
                            )))
                            .unwrap(),
                        MaybeRelocatable::RelocatableValue(value) => result_sender
                            .send(MemoryResult::Reading(PyMaybeRelocatable::RelocatableValue(
                                (value.segment_index, value.offset),
                            )))
                            .unwrap(),
                    }
                };
            }
            MemoryOperation::WriteMemory(key, value) => {
                match value {
                    PyMaybeRelocatable::Int(value) => {
                        memory.insert(&Relocatable::from(key), &value).unwrap();
                    }
                    PyMaybeRelocatable::RelocatableValue(address) => {
                        memory
                            .insert(&Relocatable::from(key), &Relocatable::from(address))
                            .unwrap();
                    }
                }
                result_sender.send(MemoryResult::Success).unwrap();
            }
            MemoryOperation::AddSegment => {
                let result = segments.add(memory);
                result_sender
                    .send(MemoryResult::Segment((result.segment_index, result.offset)))
                    .unwrap()
            }
        }
    }
}

/// Formats the sum of two numbers as string.
#[pyfunction]
fn run_cairo(py: Python) -> PyResult<()> {
    let mut memory = Memory::new();
    let mut segments = MemorySegmentManager::new();
    let (operation_sender, operation_receiver) = mpsc::channel();
    let (result_sender, result_receiver) = mpsc::channel::<MemoryResult>();
    py.allow_threads(move || {
        thread::spawn(move || {
            println!(" -- Starting python hint execution -- ");
            let gil = Python::acquire_gil();
            let py = gil.python();
            let memory =
                PyCell::new(py, PyMemory::new(operation_sender.clone(), result_receiver)).unwrap();
            py_run!(
                py,
                memory,
                r#"
            result = memory.add_segment()
            print(result)
            memory[(0,0)] = 16
            print('Memory address (0,0) has been written')
            print('Reading from (0,0): ', memory[(0,0)])
            "#
            );
            println!(" -- Ending python hint -- ");
            operation_sender.send(MemoryOperation::End).unwrap();
        });
        handle_memory_messages(
            operation_receiver,
            result_sender,
            &mut memory,
            &mut segments,
        );
    });
    Ok(())
}

/// A Python module implemented in Rust.
#[pymodule]
fn python_hints(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyMemory>()?;
    m.add_function(wrap_pyfunction!(run_cairo, m)?)?;
    Ok(())
}

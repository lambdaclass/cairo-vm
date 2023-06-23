use std::collections::HashMap;

use felt::Felt252;
use serde::Serialize;
use thiserror::Error;

use crate::{types::layout::CairoLayout, vm::trace::trace_entry::TraceEntry};

#[derive(Serialize, Debug)]
pub struct PublicMemoryEntry {
    address: usize,
    page: usize,
    value: Option<Felt252>,
}

#[derive(Serialize, Debug)]
pub struct PublicInput<'a> {
    layout: &'a str,
    layout_params: Option<&'a CairoLayout>,
    rc_min: Option<isize>,
    rc_max: Option<isize>,
    n_steps: usize,
    memory_segments: HashMap<&'a str, (usize, Option<usize>)>,
    public_memory: Vec<PublicMemoryEntry>,
}

impl<'a> PublicInput<'a> {
    pub fn new(
        memory: &[Option<Felt252>],
        layout: &'a str,
        dyn_layout_params: Option<&'a CairoLayout>,
        public_memory_addresses: &[(usize, &usize)],
        memory_segment_addresses: HashMap<&'static str, (usize, Option<usize>)>,
        trace: &[TraceEntry],
        rc_limits: Option<(isize, isize)>,
    ) -> Result<Self, PublicInputError> {
        let memory_entry =
            |addresses: &(usize, &usize)| -> Result<PublicMemoryEntry, PublicInputError> {
                let (address, page) = addresses;
                Ok(PublicMemoryEntry {
                    address: *address,
                    page: **page,
                    value: memory
                        .get(*address)
                        .ok_or(PublicInputError::MemoryNotFound(*address))?
                        .clone(),
                })
            };
        let public_memory = public_memory_addresses
            .into_iter()
            .map(memory_entry)
            .collect::<Result<Vec<_>, _>>()?;

        let (rc_min, rc_max) = if let Some(rc_limits) = rc_limits {
            (Some(rc_limits.0), Some(rc_limits.1))
        } else {
            (None, None)
        };

        let trace_first = trace.first().ok_or(PublicInputError::EmptyTrace)?;
        let trace_last = trace.last().ok_or(PublicInputError::EmptyTrace)?;

        Ok(PublicInput {
            layout,
            layout_params: dyn_layout_params,
            rc_min,
            rc_max,
            n_steps: trace.len(),
            memory_segments: {
                let mut memory_segment_addresses = memory_segment_addresses.clone();
                memory_segment_addresses.insert("program", (trace_first.pc, Some(trace_last.pc)));
                memory_segment_addresses.insert("execution", (trace_first.ap, Some(trace_last.ap)));
                memory_segment_addresses
            },
            public_memory,
        })
    }

    pub fn write(&self, file_path: &str) -> Result<(), PublicInputError> {
        let _ = std::fs::write(file_path, serde_json::to_string_pretty(&self)?)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PublicInputError {
    #[error("The trace slice provided is empty")]
    EmptyTrace,
    #[error("The provided memory doesn't contain public address {0}")]
    MemoryNotFound(usize),
    #[error("Failed to interact with the file system")]
    IO(#[from] std::io::Error),
    #[error("Failed to (de)serialize data")]
    Serde(#[from] serde_json::Error),
}

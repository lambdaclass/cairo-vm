use crate::Felt252;
use serde::Serialize;
use thiserror_no_std::Error;

use crate::{
    stdlib::{
        collections::HashMap,
        prelude::{String, Vec},
    },
    types::layout::CairoLayout,
    vm::{
        errors::{trace_errors::TraceError, vm_errors::VirtualMachineError},
        trace::trace_entry::RelocatedTraceEntry,
    },
};

#[derive(Serialize, Debug)]
pub struct PublicMemoryEntry {
    pub address: usize,
    #[serde(serialize_with = "mem_value_serde::serialize")]
    pub value: Option<Felt252>,
    pub page: usize,
}

mod mem_value_serde {
    use super::*;

    use serde::Serializer;

    pub(crate) fn serialize<S: Serializer>(
        value: &Option<Felt252>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if let Some(value) = value {
            serializer.serialize_str(&format!("{:x}", value))
        } else {
            serializer.serialize_none()
        }
    }
}

#[derive(Serialize, Debug)]
pub struct MemorySegmentAddresses {
    pub begin_addr: usize,
    pub stop_ptr: usize,
}

impl From<(usize, usize)> for MemorySegmentAddresses {
    fn from(addresses: (usize, usize)) -> Self {
        let (begin_addr, stop_ptr) = addresses;
        MemorySegmentAddresses {
            begin_addr,
            stop_ptr,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct PublicInput<'a> {
    pub layout: &'a str,
    pub rc_min: isize,
    pub rc_max: isize,
    pub n_steps: usize,
    pub memory_segments: HashMap<&'a str, MemorySegmentAddresses>,
    pub public_memory: Vec<PublicMemoryEntry>,
    #[serde(rename = "dynamic_params")]
    layout_params: Option<&'a CairoLayout>,
}

impl<'a> PublicInput<'a> {
    pub fn new(
        memory: &[Option<Felt252>],
        layout: &'a str,
        dyn_layout_params: Option<&'a CairoLayout>,
        public_memory_addresses: &[(usize, usize)],
        memory_segment_addresses: HashMap<&'static str, (usize, usize)>,
        trace: &[RelocatedTraceEntry],
        rc_limits: (isize, isize),
    ) -> Result<Self, PublicInputError> {
        let memory_entry =
            |addresses: &(usize, usize)| -> Result<PublicMemoryEntry, PublicInputError> {
                let (address, page) = addresses;
                Ok(PublicMemoryEntry {
                    address: *address,
                    page: *page,
                    value: *memory
                        .get(*address)
                        .ok_or(PublicInputError::MemoryNotFound(*address))?,
                })
            };
        let public_memory = public_memory_addresses
            .iter()
            .map(memory_entry)
            .collect::<Result<Vec<_>, _>>()?;

        let (rc_min, rc_max) = rc_limits;

        let trace_first = trace.first().ok_or(PublicInputError::EmptyTrace)?;
        let trace_last = trace.last().ok_or(PublicInputError::EmptyTrace)?;

        Ok(PublicInput {
            layout,
            layout_params: dyn_layout_params,
            rc_min,
            rc_max,
            n_steps: trace.len(),
            memory_segments: {
                let mut memory_segment_addresses = memory_segment_addresses
                    .into_iter()
                    .map(|(n, s)| (n, s.into()))
                    .collect::<HashMap<_, MemorySegmentAddresses>>();

                memory_segment_addresses.insert("program", (trace_first.pc, trace_last.pc).into());
                memory_segment_addresses
                    .insert("execution", (trace_first.ap, trace_last.ap).into());
                memory_segment_addresses
            },
            public_memory,
        })
    }

    pub fn serialize_json(&self) -> Result<String, PublicInputError> {
        serde_json::to_string_pretty(&self).map_err(PublicInputError::from)
    }
}

#[derive(Debug, Error)]
pub enum PublicInputError {
    #[error("The trace slice provided is empty")]
    EmptyTrace,
    #[error("The provided memory doesn't contain public address {0}")]
    MemoryNotFound(usize),
    #[error("Range check values are missing")]
    NoRangeCheckLimits,
    #[error("Failed to (de)serialize data")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
    #[error(transparent)]
    Trace(#[from] TraceError),
}

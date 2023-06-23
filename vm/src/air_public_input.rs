#![allow(unused)]
use std::collections::HashMap;

use felt::Felt252;

use crate::{
    types::layout::CairoLayout,
    vm::{trace::trace_entry::TraceEntry, vm_memory::memory_segments},
};

use serde::Serialize;

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
    ) -> Self {
        let public_memory = public_memory_addresses
            .into_iter()
            .map(|(address, page)| PublicMemoryEntry {
                address: *address,
                page: **page,
                value: memory[*address].clone(),
            })
            .collect();

        let (rc_min, rc_max) = if let Some(rc_limits) = rc_limits {
            (Some(rc_limits.0), Some(rc_limits.1))
        } else {
            (None, None)
        };

        PublicInput {
            layout,
            layout_params: dyn_layout_params,
            rc_min,
            rc_max,
            n_steps: trace.len(),
            memory_segments: {
                let mut memory_segment_addresses = memory_segment_addresses.clone();
                memory_segment_addresses
                    .insert("program", (trace[0].pc, Some(trace[trace.len() - 1].pc)));
                memory_segment_addresses
                    .insert("execution", (trace[0].ap, Some(trace[trace.len() - 1].ap)));

                memory_segment_addresses
            },
            public_memory,
        }
    }

    pub fn write(&self, file_path: &str) {
        std::fs::write(file_path, serde_json::to_string_pretty(&self).unwrap());
    }
}

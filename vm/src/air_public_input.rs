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
    rc_min: isize,
    rc_max: isize,
    n_steps: usize,
    memory_segments: HashMap<&'a str, (usize, Option<usize>)>,
    public_memory: Vec<PublicMemoryEntry>,
}

pub fn write_air_public_input(
    public_input_file: &str,
    memory: Vec<Option<Felt252>>,
    layout: &str,
    dyn_layout_params: Option<&CairoLayout>,
    public_memory_addresses: Vec<(usize, &usize)>,
    memory_segment_addresses: HashMap<&'static str, (usize, Option<usize>)>,
    trace: &Vec<TraceEntry>,
    rc_min: isize,
    rc_max: isize,
) {
    let public_memory = public_memory_addresses
        .into_iter()
        .map(|(address, page)| PublicMemoryEntry {
            address,
            page: *page,
            value: memory[address].clone(),
        })
        .collect();

    let initial_pc = trace[0].pc; // FIXME: what is this for?

    let public_input = PublicInput {
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
    };

    std::fs::write(
        public_input_file,
        serde_json::to_string_pretty(&public_input).unwrap(),
    );
}
// TODO: make that a method and make a publicinput::new()

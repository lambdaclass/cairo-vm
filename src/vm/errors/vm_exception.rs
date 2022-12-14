use crate::{
    serde::deserialize_program::{Attribute, Location},
    vm::runners::cairo_runner::CairoRunner,
};

use super::runner_errors::RunnerError;

pub struct VmException {
    pc: usize,
    inst_location: Option<Location>,
    inner_exc: RunnerError,
    error_attr_value: Option<String>,
}

impl VmException {
    fn from_runner_error(runner: CairoRunner, error: RunnerError, pc: usize) -> Self {
        let error_attr_value = get_error_attr_value(pc, &runner.program.error_message_attributes);
        VmException {
            pc,
            inst_location: runner.program.instruction_locations.get(&pc).cloned(),
            inner_exc: error,
            error_attr_value,
        }
    }
}

fn get_error_attr_value(pc: usize, attributes: &Vec<Attribute>) -> Option<String> {
    for attribute in attributes {
        if attribute.start_pc >= pc && attribute.end_pc <= pc {
            return Some(attribute.value.clone());
        }
    }
    None
}

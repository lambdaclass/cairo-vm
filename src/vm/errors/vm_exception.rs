use std::fmt::{self, Display};

use thiserror::Error;

use crate::{
    serde::deserialize_program::{Attribute, Location},
    vm::runners::cairo_runner::CairoRunner,
};

use super::vm_errors::VirtualMachineError;
#[derive(Debug, PartialEq, Error)]
pub struct VmException {
    pc: usize,
    inst_location: Option<Location>,
    inner_exc: VirtualMachineError,
    error_attr_value: Option<String>,
}

impl VmException {
    pub fn from_vm_error(runner: &CairoRunner, error: VirtualMachineError, pc: usize) -> Self {
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

impl Display for VmException {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = format!("Error at pc={}:\n{}", self.pc, self.inner_exc.to_string());
        let mut error_msg = String::new();
        if let Some(ref string) = self.error_attr_value {
            error_msg.push_str(string)
        }
        if let Some(ref location) = self.inst_location {
            let mut location_msg = String::new();
            let (mut location, mut message) = (location, message);
            loop {
                location_msg = format!(
                    "{}\n{}",
                    location.to_string_with_contents(message),
                    location_msg
                );
                if let Some(parent) = location.parent_location {
                    (location, message) = (&parent.0, parent.1)
                } else {
                    break;
                }
            }
        } else {
            error_msg.push_str(&format!("{}\n", message));
        }
        // Traceback & Notes
        write!(f, "{}", error_msg)
    }
}

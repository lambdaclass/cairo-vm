use std::fmt::{self, Display};

use thiserror::Error;

use crate::{serde::deserialize_program::Location, vm::runners::cairo_runner::CairoRunner};

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
        let error_attr_value = get_error_attr_value(pc, runner);
        VmException {
            pc,
            inst_location: get_location(&pc, runner),
            inner_exc: error,
            error_attr_value,
        }
    }
}

pub fn get_error_attr_value(pc: usize, runner: &CairoRunner) -> Option<String> {
    for attribute in &runner.program.error_message_attributes {
        if attribute.start_pc <= pc && attribute.end_pc > pc {
            return Some(format!("Error message: {}\n", attribute.value));
        }
    }
    None
}

pub fn get_location(pc: &usize, runner: &CairoRunner) -> Option<Location> {
    runner
        .program
        .instruction_locations
        .as_ref()?
        .get(pc)
        .cloned()
}

impl Display for VmException {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Build initial message
        let message = format!("Error at pc={}:\n{}", self.pc, self.inner_exc);
        let mut error_msg = String::new();
        // Add error attribute value
        if let Some(ref string) = self.error_attr_value {
            error_msg.push_str(string)
        }
        // Add location information
        if let Some(ref location) = self.inst_location {
            let mut location_msg = String::new();
            let (mut location, mut message) = (location, &message);
            loop {
                location_msg = format!("{}\n{}", location.to_string(message), location_msg);
                // Add parent location info
                if let Some(parent) = &location.parent_location {
                    (location, message) = (&parent.0, &parent.1)
                } else {
                    break;
                }
            }
            error_msg.push_str(&location_msg)
        } else {
            error_msg.push_str(&format!("{}\n", message));
        }
        // Write error message
        write!(f, "{}", error_msg)
    }
}

impl Location {
    ///  Prints the location with the passed message.
    pub fn to_string(&self, message: &String) -> String {
        let msg_prefix = if message.is_empty() { "" } else { ":" };
        format!(
            "{}:{}:{}{}{}",
            self.input_file.filename, self.start_line, self.start_col, msg_prefix, message
        )
    }
}
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::serde::deserialize_program::{Attribute, InputFile};
    use crate::types::program::Program;
    use crate::utils::test_utils::*;

    use super::*;
    #[test]
    fn get_vm_exception_from_vm_error() {
        let pc = 1;
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: None,
            start_line: 1,
            start_col: 1,
        };
        let program =
            program!(instruction_locations = Some(HashMap::from([(pc, location.clone())])),);
        let runner = cairo_runner!(program);
        let vm_excep = VmException {
            pc,
            inst_location: Some(location),
            inner_exc: VirtualMachineError::CouldntPopPositions,
            error_attr_value: None,
        };
        assert_eq!(
            VmException::from_vm_error(&runner, VirtualMachineError::CouldntPopPositions, pc),
            vm_excep
        )
    }

    #[test]
    fn location_to_string_no_message() {
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: None,
            start_line: 1,
            start_col: 1,
        };
        let message = String::new();
        assert_eq!(
            location.to_string(&message),
            String::from("Folder/file.cairo:1:1")
        )
    }

    #[test]
    fn location_to_string_with_message() {
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: None,
            start_line: 1,
            start_col: 1,
        };
        let message = String::from("While expanding the reference");
        assert_eq!(
            location.to_string(&message),
            String::from("Folder/file.cairo:1:1:While expanding the reference")
        )
    }

    #[test]
    fn vm_exception_display_instruction_no_location_no_attributes() {
        let vm_excep = VmException {
            pc: 2,
            inst_location: None,
            inner_exc: VirtualMachineError::FailedToComputeOperands,
            error_attr_value: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Error at pc=2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands
            )
        )
    }

    #[test]
    fn vm_exception_display_instruction_no_location_with_attributes() {
        let vm_excep = VmException {
            pc: 2,
            inst_location: None,
            inner_exc: VirtualMachineError::FailedToComputeOperands,
            error_attr_value: Some(String::from("Error message: Block may fail\n")),
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Error message: Block may fail\nError at pc=2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands
            )
        )
    }

    #[test]
    fn vm_exception_display_instruction_no_attributes_no_parent() {
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: None,
            start_line: 1,
            start_col: 1,
        };
        let vm_excep = VmException {
            pc: 2,
            inst_location: Some(location),
            inner_exc: VirtualMachineError::FailedToComputeOperands,
            error_attr_value: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Folder/file.cairo:1:1:Error at pc=2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands
            )
        )
    }

    #[test]
    fn vm_exception_display_instruction_no_attributes_with_parent() {
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: Some((
                Box::new(Location {
                    end_line: 3,
                    end_col: 3,
                    input_file: InputFile {
                        filename: String::from("Folder/file_b.cairo"),
                    },
                    parent_location: None,
                    start_line: 2,
                    start_col: 2,
                }),
                String::from("While expanding the reference:"),
            )),
            start_line: 1,
            start_col: 1,
        };
        let vm_excep = VmException {
            pc: 2,
            inst_location: Some(location),
            inner_exc: VirtualMachineError::FailedToComputeOperands,
            error_attr_value: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Folder/file_b.cairo:2:2:While expanding the reference:\nFolder/file.cairo:1:1:Error at pc=2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands
            )
        )
    }

    #[test]
    fn get_error_attr_value_some() {
        let attributes = vec![Attribute {
            name: String::from("Error message"),
            start_pc: 1,
            end_pc: 5,
            value: String::from("Invalid hash"),
        }];
        let program = program!(error_message_attributes = attributes,);
        let runner = cairo_runner!(program);
        assert_eq!(
            get_error_attr_value(2, &runner),
            Some(String::from("Error message: Invalid hash\n"))
        );
    }

    #[test]
    fn get_error_attr_value_none() {
        let attributes = vec![Attribute {
            name: String::from("Error message"),
            start_pc: 1,
            end_pc: 5,
            value: String::from("Invalid hash"),
        }];
        let program = program!(error_message_attributes = attributes,);
        let runner = cairo_runner!(program);
        assert_eq!(get_error_attr_value(5, &runner), None);
    }

    #[test]
    fn get_location_some() {
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: None,
            start_line: 1,
            start_col: 1,
        };
        let program =
            program!(instruction_locations = Some(HashMap::from([(2, location.clone())])),);
        let runner = cairo_runner!(program);
        assert_eq!(get_location(&2, &runner), Some(location));
    }

    #[test]
    fn get_location_none() {
        let location = Location {
            end_line: 2,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("Folder/file.cairo"),
            },
            parent_location: None,
            start_line: 1,
            start_col: 1,
        };
        let program = program!(instruction_locations = Some(HashMap::from([(2, location)])),);
        let runner = cairo_runner!(program);
        assert_eq!(get_location(&3, &runner), None);
    }
}

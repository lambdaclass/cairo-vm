use std::{
    fmt::{self, Display},
    fs::File,
    io::{BufReader, Read},
    path::Path,
};

use thiserror::Error;

use crate::{
    serde::deserialize_program::Location,
    vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
};

use super::vm_errors::VirtualMachineError;
#[derive(Debug, PartialEq, Error)]
pub struct VmException {
    pc: usize,
    inst_location: Option<Location>,
    inner_exc: VirtualMachineError,
    error_attr_value: Option<String>,
    traceback: Option<String>,
}

impl VmException {
    pub fn from_vm_error(
        runner: &CairoRunner,
        vm: &VirtualMachine,
        error: VirtualMachineError,
    ) -> Self {
        let pc = vm.run_context.pc.offset;
        let error_attr_value = get_error_attr_value(pc, runner);
        VmException {
            pc,
            inst_location: get_location(pc, runner),
            inner_exc: error,
            error_attr_value,
            traceback: get_traceback(vm, runner),
        }
    }
}

pub fn get_error_attr_value(pc: usize, runner: &CairoRunner) -> Option<String> {
    let mut errors = String::new();
    for attribute in &runner.program.error_message_attributes {
        if attribute.start_pc <= pc && attribute.end_pc > pc {
            errors.push_str(&format!("Error message: {}\n", attribute.value));
        }
    }
    (!errors.is_empty()).then(|| errors)
}

pub fn get_location(pc: usize, runner: &CairoRunner) -> Option<Location> {
    runner
        .program
        .instruction_locations
        .as_ref()?
        .get(&pc)
        .cloned()
}

// Returns the traceback at the current pc.
pub fn get_traceback(vm: &VirtualMachine, runner: &CairoRunner) -> Option<String> {
    let mut traceback = String::new();
    for (_fp, traceback_pc) in vm.get_traceback_entries() {
        if let Some(ref attr) = get_error_attr_value(traceback_pc.offset, runner) {
            traceback.push_str(attr)
        }
        match get_location(traceback_pc.offset, runner) {
            Some(location) => traceback.push_str(&format!(
                "{}\n",
                location.to_string_with_content(&format!("(pc=0:{})\n", traceback_pc.offset))
            )),
            None => traceback.push_str(&format!(
                "Unknown location (pc=0:{})\n",
                traceback_pc.offset
            )),
        }
    }
    (!traceback.is_empty())
        .then(|| format!("Cairo traceback (most recent call last):\n{}", traceback))
}

impl Display for VmException {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Build initial message
        let message = format!("Error at pc=0:{}:\n{}\n", self.pc, self.inner_exc);
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
                location_msg = format!(
                    "{}\n{}",
                    location.to_string_with_content(message),
                    location_msg
                );
                // Add parent location info
                if let Some(parent) = &location.parent_location {
                    (location, message) = (&parent.0, &parent.1)
                } else {
                    break;
                }
            }
            error_msg.push_str(&location_msg)
        } else {
            error_msg.push_str(&format!("{}", message));
        }
        if let Some(ref string) = self.traceback {
            error_msg.push_str(&format!("{}\n", string));
        }
        // Write error message
        write!(f, "{}", error_msg)
    }
}

impl Location {
    ///  Prints the location with the passed message.
    pub fn to_string(&self, message: &String) -> String {
        let msg_prefix = if message.is_empty() { "" } else { ": " };
        format!(
            "{}:{}:{}{}{}",
            self.input_file.filename, self.start_line, self.start_col, msg_prefix, message
        )
    }

    pub fn to_string_with_content(&self, message: &String) -> String {
        let mut string = self.to_string(message);
        let input_file_path = Path::new(&self.input_file.filename);
        if let Ok(file) = File::open(input_file_path) {
            let mut reader = BufReader::new(file);
            string.push_str(&self.get_location_marks(&mut reader));
        }
        string
    }

    pub fn get_location_marks(&self, file_contents: &mut impl Read) -> String {
        let mut contents = String::new();
        // If this read fails, the string will be left empty, so we can ignore the result
        let _ = file_contents.read_to_string(&mut contents);
        let split_lines: Vec<&str> = contents.split('\n').collect();
        if !(0 < self.start_line && ((self.start_line - 1) as usize) < split_lines.len()) {
            return String::new();
        }
        let start_line = split_lines[((self.start_line - 1) as usize)];
        let start_col = self.start_col as usize;
        let mut result = format!("{}\n", start_line);
        let end_col = if self.start_line == self.end_line {
            self.end_col as usize
        } else {
            start_line.len() + 1
        };
        let left_margin: String = vec![' '; start_col - 1].into_iter().collect();
        if end_col > start_col + 1 {
            let highlight: String = vec!['*'; end_col - start_col - 2].into_iter().collect();
            result.push_str(&format!("{}^{}^", left_margin, highlight));
        } else {
            result.push_str(&format!("{}^", left_margin))
        }
        result
    }
}
#[cfg(test)]
mod test {
    use num_bigint::{BigInt, Sign};
    use std::collections::HashMap;
    use std::path::Path;

    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::serde::deserialize_program::{Attribute, InputFile};
    use crate::types::program::Program;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;

    use super::*;
    #[test]
    fn get_vm_exception_from_vm_error() {
        let pc = 0;
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
            traceback: None,
        };
        assert_eq!(
            VmException::from_vm_error(&runner, &vm!(), VirtualMachineError::CouldntPopPositions,),
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
            String::from("Folder/file.cairo:1:1: While expanding the reference")
        )
    }

    #[test]
    fn vm_exception_display_instruction_no_location_no_attributes() {
        let vm_excep = VmException {
            pc: 2,
            inst_location: None,
            inner_exc: VirtualMachineError::FailedToComputeOperands(
                "op0".to_string(),
                Relocatable::from((0, 4)),
            ),
            error_attr_value: None,
            traceback: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Error at pc=0:2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands(
                    "op0".to_string(),
                    Relocatable::from((0, 4))
                )
            )
        )
    }

    #[test]
    fn vm_exception_display_instruction_no_location_with_attributes() {
        let vm_excep = VmException {
            pc: 2,
            inst_location: None,
            inner_exc: VirtualMachineError::FailedToComputeOperands(
                "op0".to_string(),
                Relocatable::from((0, 4)),
            ),
            error_attr_value: Some(String::from("Error message: Block may fail\n")),
            traceback: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Error message: Block may fail\nError at pc=0:2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands(
                    "op0".to_string(),
                    Relocatable::from((0, 4))
                )
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
            inner_exc: VirtualMachineError::FailedToComputeOperands(
                "op0".to_string(),
                Relocatable::from((0, 4)),
            ),
            error_attr_value: None,
            traceback: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Folder/file.cairo:1:1: Error at pc=0:2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands(
                    "op0".to_string(),
                    Relocatable::from((0, 4))
                )
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
            inner_exc: VirtualMachineError::FailedToComputeOperands(
                "op0".to_string(),
                Relocatable::from((0, 4)),
            ),
            error_attr_value: None,
            traceback: None,
        };
        assert_eq!(
            vm_excep.to_string(),
            format!(
                "Folder/file_b.cairo:2:2: While expanding the reference:\nFolder/file.cairo:1:1: Error at pc=0:2:\n{}\n",
                VirtualMachineError::FailedToComputeOperands("op0".to_string(), Relocatable::from((0, 4)))
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
        assert_eq!(get_location(2, &runner), Some(location));
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
        assert_eq!(get_location(3, &runner), None);
    }

    #[test]
    fn get_traceback_bad_dict_update() {
        let program = Program::from_file(
            Path::new("cairo_programs/bad_programs/bad_dict_update.json"),
            Some("main"),
        )
        .expect("Call to `Program::from_file()` failed.");

        let mut hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program, "all", false);
        let mut vm = vm!();

        let end = cairo_runner.initialize(&mut vm).unwrap();
        assert!(cairo_runner
            .run_until_pc(end, &mut vm, &mut hint_processor)
            .is_err());
        let expected_traceback = String::from("Cairo traceback (most recent call last):\ncairo_programs/bad_programs/bad_dict_update.cairo:10:5: (pc=0:34)\n    dict_update{dict_ptr=my_dict}(key=2, prev_value=3, new_value=4);\n    ^*************************************************************^\n");
        assert_eq!(get_traceback(&vm, &cairo_runner), Some(expected_traceback));
    }

    #[test]
    fn get_traceback_bad_usort() {
        let program = Program::from_file(
            Path::new("cairo_programs/bad_programs/bad_usort.json"),
            Some("main"),
        )
        .expect("Call to `Program::from_file()` failed.");

        let mut hint_processor = BuiltinHintProcessor::new_empty();
        let mut cairo_runner = cairo_runner!(program, "all", false);
        let mut vm = vm!();

        let end = cairo_runner.initialize(&mut vm).unwrap();
        assert!(cairo_runner
            .run_until_pc(end, &mut vm, &mut hint_processor)
            .is_err());
        let expected_traceback = String::from("Cairo traceback (most recent call last):\ncairo_programs/bad_programs/bad_usort.cairo:91:48: (pc=0:97)\n    let (output_len, output, multiplicities) = usort(input_len=3, input=input_array);\n                                               ^***********************************^\ncairo_programs/bad_programs/bad_usort.cairo:36:5: (pc=0:30)\n    verify_usort{output=output}(\n    ^**************************^\ncairo_programs/bad_programs/bad_usort.cairo:64:5: (pc=0:60)\n    verify_multiplicity(multiplicity=multiplicity, input_len=input_len, input=input, value=value);\n    ^*******************************************************************************************^\n");
        assert_eq!(get_traceback(&vm, &cairo_runner), Some(expected_traceback));
    }

    #[test]
    fn location_to_string_with_contents_no_contents() {
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
            location.to_string_with_content(&message),
            String::from("Folder/file.cairo:1:1: While expanding the reference")
        )
    }

    #[test]
    fn location_to_string_with_contents() {
        let location = Location {
            end_line: 5,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("cairo_programs/bad_programs/bad_usort.cairo"),
            },
            parent_location: None,
            start_line: 5,
            start_col: 1,
        };
        let message = String::from("Error at pc=0:75:\n");
        assert_eq!(
            location.to_string_with_content(&message),
            String::from("cairo_programs/bad_programs/bad_usort.cairo:5:1: Error at pc=0:75:\nfunc usort{range_check_ptr}(input_len: felt, input: felt*) -> (\n^")
        )
    }

    #[test]
    fn location_to_string_with_contents_no_file() {
        let location = Location {
            end_line: 5,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("cairo_programs/bad_prtypoograms/bad_usort.cairo"),
            },
            parent_location: None,
            start_line: 5,
            start_col: 1,
        };
        let message = String::from("Error at pc=0:75:\n");
        assert_eq!(
            location.to_string_with_content(&message),
            String::from(
                "cairo_programs/bad_prtypoograms/bad_usort.cairo:5:1: Error at pc=0:75:\n"
            )
        )
    }

    #[test]
    fn location_get_location_marks() {
        let location = Location {
            end_line: 5,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("cairo_programs/bad_programs/bad_usort.cairo"),
            },
            parent_location: None,
            start_line: 5,
            start_col: 1,
        };
        let input_file_path = Path::new(&location.input_file.filename);
        let file = File::open(input_file_path).expect("Failed to open file");
        let mut reader = BufReader::new(file);
        assert_eq!(
            location.get_location_marks(&mut reader),
            String::from("func usort{range_check_ptr}(input_len: felt, input: felt*) -> (\n^")
        )
    }

    #[test]
    fn location_get_location_marks_empty_file() {
        let location = Location {
            end_line: 5,
            end_col: 2,
            input_file: InputFile {
                filename: String::from("cairo_programs/bad_programs/bad_usort.cairo"),
            },
            parent_location: None,
            start_line: 5,
            start_col: 1,
        };
        let mut reader: &[u8] = &[];
        assert_eq!(location.get_location_marks(&mut reader), String::from(""))
    }
}

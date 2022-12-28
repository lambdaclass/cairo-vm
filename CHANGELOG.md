2022-12-28
* Add traceback to VmException
    * PR: [#657](https://github.com/lambdaclass/cairo-rs/pull/657)
    * Main functionality changes: `VmException` now contains a traceback in the form of a String which lists the locations (consisting of filename, line, column and pc) of the calls leading to the error.
    * Public API changes: 
        * `traceback` field added to `VmException` struct
        * `VmException::from_vm_error()` signature changed from `pub fn from_vm_error(runner: &CairoRunner, error: VirtualMachineError, pc: usize) -> Self` to `pub fn from_vm_error(runner: &CairoRunner, vm: &VirtualMachine, error: VirtualMachineError) -> Self`
        * `get_location()` signature changed from `pub fn get_location(pc: &usize, runner: &CairoRunner) -> Option<Location>` to `pub fn get_location(pc: usize, runner: &CairoRunner) -> Option<Location>`
        * `decode_instruction()` signature changed from `pub fn decode_instruction(encoded_instr: i64, mut imm: Option<BigInt>) -> Result<instruction::Instruction, VirtualMachineError>` to `pub fn decode_instruction(encoded_instr: i64, mut imm: Option<&BigInt>) -> Result<instruction::Instruction, VirtualMachineError>`
        * Minor changes in `VmExcepion` field's string format to mirror their cairo-lang conterparts.

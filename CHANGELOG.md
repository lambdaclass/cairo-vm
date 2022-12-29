* Add traceback to VmException [#657](https://github.com/lambdaclass/cairo-rs/pull/657)
    * Public API changes: 
        * `traceback` field added to `VmException` struct
        * `pub fn from_vm_error(runner: &CairoRunner, error: VirtualMachineError, pc: usize) -> Self` is now `pub fn from_vm_error(runner: &CairoRunner, vm: &VirtualMachine, error: VirtualMachineError) -> Self`
        * `pub fn get_location(pc: &usize, runner: &CairoRunner) -> Option<Location>` is now `pub fn get_location(pc: usize, runner: &CairoRunner) -> Option<Location>`
        * `pub fn decode_instruction(encoded_instr: i64, mut imm: Option<BigInt>) -> Result<instruction::Instruction, VirtualMachineError>` is now `pub fn decode_instruction(encoded_instr: i64, mut imm: Option<&BigInt>) -> Result<instruction::Instruction, VirtualMachineError>`
        * `VmExcepion` field's string format now mirror their cairo-lang conterparts.

* Add input file contents to traceback [#666](https://github.com/lambdaclass/cairo-rs/pull/666/files)
    * Public Api changes:
        * `VirtualMachineError` enum variants containing `MaybeRelocatable` and/or `Relocatable` values now use the `Display` format instead of `Debug` in their `Display` implementation
        * `get_traceback` now adds the source code line to each traceback entry

* Use hint location instead of instruction location when building VmExceptions from hint failure [#673](https://github.com/lambdaclass/cairo-rs/pull/673/files)
    * Public Api changes:
    * `hints` field added to `InstructionLocation`
    * `Program.instruction_locations` type changed from `Option<HashMap<usize, Location>>` to `Option<HashMap<usize, InstructionLocation>>`
    * `VirtualMachineError`s produced by `HintProcessor::execute_hint()` will be wrapped in a `VirtualMachineError::Hint` error containing their hint_index
    * `get_location()` now receives an an optional usize value `hint_index`, used to obtain hint locations

* Add new error type `HintError` [#676](https://github.com/lambdaclass/cairo-rs/pull/676)
    * Public Api changes:
        * `HintProcessor::execute_hint()` now returns a `HintError` instead of a `VirtualMachineError`
        * helper functions on `hint_processor_utils.rs` now return a `HintError`


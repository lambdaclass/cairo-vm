## Cairo-VM Changelog

#### Upcoming Changes

* Add missing hint on cairo_secp lib [#989]:

    `BuiltinHintProcessor` now supports the following hint:
    ```python
        from starkware.cairo.common.cairo_secp.secp_utils import SECP_P
        q, r = divmod(pack(ids.val, PRIME), SECP_P)
        assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
        ids.q = q % PRIME
    ```

* Add missing hint on cairo_secp lib [#986]:
    `BuiltinHintProcessor` now supports the following hint:
    ```python
        from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
        from starkware.python.math_utils import div_mod

        # Compute the slope.
        x = pack(ids.pt.x, PRIME)
        y = pack(ids.pt.y, PRIME)
        value = slope = div_mod(3 * x ** 2, 2 * y, SECP_P)
    ```

* Add missing hint on cairo_secp lib [#984]:
    `BuiltinHintProcessor` now supports the following hint:
    ```python
        from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
        from starkware.python.math_utils import div_mod

        # Compute the slope.
        x0 = pack(ids.pt0.x, PRIME)
        y0 = pack(ids.pt0.y, PRIME)
        x1 = pack(ids.pt1.x, PRIME)
        y1 = pack(ids.pt1.y, PRIME)
        value = slope = div_mod(y0 - y1, x0 - x1, SECP_P)
    ```

* Move `Memory` into `MemorySegmentManager` [#830](https://github.com/lambdaclass/cairo-rs/pull/830)
    * Structural changes:
        * Remove `memory: Memory` field from `VirtualMachine`
        * Add `memory: Memory` field to `MemorySegmentManager`
    * As a result of this, multiple public methods' signatures changed:
        * `BuiltinRunner` (and its inner enum types):
            * `initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory)` -> `initialize_segments(&mut self, segments: &mut MemorySegmentManager)`
            * `final_stack(&mut self, segments: &MemorySegmentManager, memory: &Memory, stack_pointer: Relocatable) -> Result<Relocatable, RunnerError>` -> `final_stack(&mut self, segments: &MemorySegmentManager, stack_pointer: Relocatable) -> Result<Relocatable, RunnerError>`
        * `MemorySegmentManager`
            * `add(&mut self, memory: &mut Memory) -> Relocatable` -> `add(&mut self) -> Relocatable`
            * `add_temporary_segment(&mut self, memory: &mut Memory) -> Relocatable` -> `add_temporary_segment(&mut self) -> Relocatable`
            * `load_data(&mut self, memory: &mut Memory, ptr: &MaybeRelocatable, data: &Vec<MaybeRelocatable>) -> Result<MaybeRelocatable, MemoryError>` -> `load_data(&mut self, ptr: &MaybeRelocatable, data: &Vec<MaybeRelocatable>) -> Result<MaybeRelocatable, MemoryError>`
            * `compute_effective_sizes(&mut self, memory: &Memory) -> &Vec<usize>` -> `compute_effective_sizes(&mut self) -> &Vec<usize>`
            * `gen_arg(&mut self, arg: &dyn Any, memory: &mut Memory) -> Result<MaybeRelocatable, VirtualMachineError>` -> `gen_arg(&mut self, arg: &dyn Any) -> Result<MaybeRelocatable, VirtualMachineError>`
            * `gen_cairo_arg(&mut self, arg: &CairoArg, memory: &mut Memory) -> Result<MaybeRelocatable, VirtualMachineError>` -> `gen_cairo_arg(&mut self, arg: &CairoArg) -> Result<MaybeRelocatable, VirtualMachineError>`
            * `write_arg(&mut self, memory: &mut Memory, ptr: &Relocatable, arg: &dyn Any) -> Result<MaybeRelocatable, MemoryError>` -> `write_arg(&mut self, ptr: &Relocatable, arg: &dyn Any) -> Result<MaybeRelocatable, MemoryError>`

* Refactor `Memory::relocate memory` [#784](https://github.com/lambdaclass/cairo-rs/pull/784)
    * Bugfixes:
        * `Memory::relocate_memory` now moves data in the temporary memory relocated by a relocation rule to the real memory
    * Aditional Notes:
        * When relocating temporary memory produces clashes with pre-existing values in the real memory, an InconsistentMemory error is returned instead of keeping the last inserted value. This differs from the original implementation.
        
* Restrict addresses to Relocatable + fix some error variants used in signature.rs [#792](https://github.com/lambdaclass/cairo-rs/pull/792)
    * Public Api Changes:
        * Change `ValidationRule` inner type to `Box<dyn Fn(&Memory, &Relocatable) -> Result<Vec<Relocatable>, MemoryError>>`.
        * Change `validated_addresses` field of `Memory` to `HashSet<Relocatable>`.
        * Change `validate_memory_cell(&mut self, address: &MaybeRelocatable) -> Result<(), MemoryError>` to `validate_memory_cell(&mut self, addr: &Relocatable) -> Result<(), MemoryError>`.

* Add `VmException` to `CairoRunner::run_from_entrypoint`[#775](https://github.com/lambdaclass/cairo-rs/pull/775)
    * Public Api Changes:
        * Change error return type of `CairoRunner::run_from_entrypoint` to `CairoRunError`.
        * Convert `VirtualMachineError`s outputed during the vm run to `VmException` in `CairoRunner::run_from_entrypoint`.
        * Make `VmException` fields public

* Fix `BuiltinRunner::final_stack` and remove quick fix [#778](https://github.com/lambdaclass/cairo-rs/pull/778)
    * Public Api changes:
        * Various changes to public `BuiltinRunner` method's signatures:
            * `final_stack(&self, vm: &VirtualMachine, pointer: Relocatable) -> Result<(Relocatable, usize), RunnerError>` to `final_stack(&mut self, segments: &MemorySegmentManager, memory: &Memory, pointer: Relocatable) -> Result<Relocatable,RunnerError>`.
            * `get_used_cells(&self, vm: &VirtualMachine) -> Result<usize, MemoryError>` to  `get_used_cells(&self, segments: &MemorySegmentManager) -> Result<usize, MemoryError>`.
            * `get_used_instances(&self, vm: &VirtualMachine) -> Result<usize, MemoryError>` to `get_used_instances(&self, segments: &MemorySegmentManager) -> Result<usize, MemoryError>`.
    * Bugfixes:
        * `BuiltinRunner::final_stack` now updates the builtin's stop_ptr instead of returning it. This replaces the bugfix on PR #768.

#### [0.1.3] - 2023-01-26
* Add secure_run flag + integrate verify_secure_runner into cairo-run [#771](https://github.com/lambdaclass/cairo-rs/pull/777)
    * Public Api changes:
        * Add command_line argument `secure_run`
        * Add argument `secure_run: Option<bool>` to `cairo_run`
        * `verify_secure_runner` is now called inside `cairo-run` when `secure_run` is set to true or when it not set and the run is not on `proof_mode`
    * Bugfixes:
        * `EcOpBuiltinRunner::deduce_memory_cell` now checks that both points are on the curve instead of only the first one
        * `EcOpBuiltinRunner::deduce_memory_cell` now returns the values of the point coordinates instead of the indices when a `PointNotOnCurve` error is returned

* Refactor `Refactor verify_secure_runner` [#768](https://github.com/lambdaclass/cairo-rs/pull/768)
    * Public Api changes:
        * Remove builtin name from the return value of `BuiltinRunner::get_memory_segment_addresses`
        * Simplify the return value of `CairoRunner::get_builtin_segments_info` to `Vec<(usize, usize)>`
        * CairoRunner::read_return_values now receives a mutable reference to VirtualMachine
    * Bugfixes:
        * CairoRunner::read_return_values now updates the `stop_ptr` of each builtin after calling `BuiltinRunner::final_stack`

* Use CairoArg enum instead of Any in CairoRunner::run_from_entrypoint [#686](https://github.com/lambdaclass/cairo-rs/pull/686)
    * Public Api changes:
        * Remove `Result` from `MaybeRelocatable::mod_floor`, it now returns a `MaybeRelocatable` 
        * Add struct `CairoArg`
        * Change `arg` argument of `CairoRunner::run_from_entrypoint` from `Vec<&dyn Any>` to `&[&CairoArg]`
        * Remove argument `typed_args` from `CairoRunner::run_from_entrypoint`
        * Remove no longer used method `gen_typed_arg` from `VirtualMachine` & `MemorySegmentManager`
        * Add methods `MemorySegmentManager::gen_cairo_arg` & `MemorySegmentManager::write_simple_args` as typed counterparts to `MemorySegmentManager::gen_arg` & `MemorySegmentManager::write_arg`
        
#### [0.1.1] - 2023-01-11

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
* Default implementation of compile_hint [#680](https://github.com/lambdaclass/cairo-rs/pull/680)
    * Internal changes: 
        * Make the `compile_hint` implementation which was in the `BuiltinHintProcessor` the default implementation in the trait. 
* Add new error type `HintError` [#676](https://github.com/lambdaclass/cairo-rs/pull/676)
    * Public Api changes:
        * `HintProcessor::execute_hint()` now returns a `HintError` instead of a `VirtualMachineError`
        * Helper functions on `hint_processor_utils.rs` now return a `HintError`
* Change the Dictionary used in dict hints to store MaybeRelocatable instead of BigInt [#687](https://github.com/lambdaclass/cairo-rs/pull/687)
    * Public Api changes:
        * `DictManager`, its dictionaries, and all dict module hints implemented in rust now use `MaybeRelocatable` for keys and values instead of `BigInt`
        * Add helper functions that allow extracting ids variables as `MaybeRelocatable`: `get_maybe_relocatable_from_var_name` & `get_maybe_relocatable_from_reference`
        * Change inner value type of dict-related `HintError` variants to `MaybeRelocatable`
        
* Implement `substitute_error_message_attribute_references` [#689] (https://github.com/lambdaclass/cairo-rs/pull/689)
    * Public Api changes:
        * Remove `error_message_attributes` field from `VirtualMachine`, and `VirtualMachine::new`
        * Add `flow_tracking_data` field to `Attribute`
        * `get_error_attr_value` now replaces the references in the error message with the corresponding cairo values.
        * Remove duplicated handling of error attribute messages leading to duplicated into in the final error display.
* Fix multiplicative inverse bug [#697](https://github.com/lambdaclass/cairo-rs/pull/697) [#698](https://github.com/lambdaclass/cairo-rs/pull/698). The VM was using integer division rather than prime field inverse when deducing `op0` or `op1` for the multiplication opcode

#### [0.1.0] - 2022-12-30
* Add traceback to VmException [#657](https://github.com/lambdaclass/cairo-rs/pull/657)
    * Public API changes: 
        * `traceback` field added to `VmException` struct
        * `pub fn from_vm_error(runner: &CairoRunner, error: VirtualMachineError, pc: usize) -> Self` is now `pub fn from_vm_error(runner: &CairoRunner, vm: &VirtualMachine, error: VirtualMachineError) -> Self`
        * `pub fn get_location(pc: &usize, runner: &CairoRunner) -> Option<Location>` is now `pub fn get_location(pc: usize, runner: &CairoRunner) -> Option<Location>`
        * `pub fn decode_instruction(encoded_instr: i64, mut imm: Option<BigInt>) -> Result<instruction::Instruction, VirtualMachineError>` is now `pub fn decode_instruction(encoded_instr: i64, mut imm: Option<&BigInt>) -> Result<instruction::Instruction, VirtualMachineError>`
        * `VmExcepion` field's string format now mirror their cairo-lang conterparts.

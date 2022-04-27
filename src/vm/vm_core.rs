use num_bigint::BigUint;
use std::collections::HashMap;
mod maybe_relocatable;
mod memory_dict;

struct RunContext {
    memory: MemoryDict,
    pc: MaybeRelocatable,
    ap: MaybeRelocatable,
    fp: MaybeRelocatable,
    prime: BigUint,
}

struct VirtualMachine {
    run_context: RunContext,
    prime: BigUint,
    builtin_runners: Option<HashMap<..., ...>>,
    exec_scopes: Vec<HashMap<..., ...>>,
    enter_scope: ,
    hints: HashMap<MaybeRelocatable, Vec<CompiledHint>>,
    hint_locals: HashMap<..., ...>,
    hint_pc_and_index: HashMap<i32, (MaybeRelocatable, i32)>,
    static_locals: Option<HashMap<..., ...>>,
    intruction_debug_info: HashMap<MaybeRelocatable, InstructionLocation>,
    debug_file_contents: HashMap<String, String>,
    error_message_attributes: Vec<VmAttributeScope>,
    program: ProgramBase,
    program_base: Option<MaybeRelocatable>,
    validated_memory: ValidatedMemoryDict,
    auto_deduction: HashMap<i32, Vec<(Rule, ())>>,
    accessesed_addresses: Vec<MaybeRelocatable>,
    trace: Vec<TraceEntry>,
    current_step: BigUint,
    skip_instruction_execution: bool,
}

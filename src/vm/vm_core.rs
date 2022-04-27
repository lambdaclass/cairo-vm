use num_bigint::BigUint;
use std::collections::HashMap;
mod relocatable;
mod memory_dict;
mod validated_memory_dict;
mod trace_entry;
mod builtin_runner;

use::maybe_relocatable::MaybeRelocatable;
use::memory_dict::MemoryDict;
use::validated_memory_dict::ValidatedMemoryDict;
use::relocatable::MaybeRelocatable;
use::trace_entry::TraceEntry;
use::builtin_runner::BuitinRunner;

struct Operands {
    dst: MaybeRelocatable,
    res: Option<MaybeRelocatable>,
    op0: MaybeRelocatable,
    op1: MaybeRelocatable
}

struct RunContext {
    memory: MemoryDict,
    pc: MaybeRelocatable,
    ap: MaybeRelocatable,
    fp: MaybeRelocatable,
    prime: BigUint
}

pub struct VirtualMachine {
    run_context: RunContext,
    prime: BigUint,
    builtin_runners: Option<HashMap<String, BuiltinRunner>>,
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
    skip_instruction_execution: bool
}

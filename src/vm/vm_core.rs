use num_bigint::BigUint;
use std::collections::HashMap;

struct RunContext {
    memory: ,
    pc: ,
    ap: ,
    fp: ,
}

struct VirtualMachine {
    prime: BigUint,
    builtin_runners: ,
    exec_scopes: Vec<HashMap<..., ...>>,
    enter_scope: ,
    hints: HashMap<..., Vec<...>>,
    hint_pc_and_index: HashMap<i32, (..., i32)>,
    intruction_debug_info: HashMap<..., ...>,
    debug_file_contents: HashMap<String, String>,
    error_message_attributes: Vec<...>,
    program: ...,
    validated_memory: HashMap<...>
}

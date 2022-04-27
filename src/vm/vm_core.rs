use num_bigint::BigUint;
use std::collections::HashMap;
mod relocatable;
mod memory_dict;
mod validated_memory_dict;
mod trace_entry;
mod builtin_runner;
mod instruction;

use::maybe_relocatable::MaybeRelocatable;
use::memory_dict::MemoryDict;
use::validated_memory_dict::ValidatedMemoryDict;
use::relocatable::MaybeRelocatable;
use::trace_entry::TraceEntry;
use::builtin_runner::BuitinRunner;
use::instruction::Instruction;

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

impl RunContext {
    ///Returns the encoded instruction (the value at pc) and the immediate value (the value at
    ///pc + 1, if it exists in the memory).
    fn get_instruction_encoding(&self) -> Result<(BigUint, Option<BigUint>), VirtualMachineError> {
        let instruction_encoding = self.memory.[self.pc];
        match instruction_encoding{
            MaybeRelocatable::Int => {
                let imm_addr = (self.pc + 1) % self.prime;
                let optional_imm = self.memory.get(imm_addr);
                Ok(instruction_encoding, optional_imm);
            },
            _ => Err(VirtualMachineError::InvalidInstructionEcodingError(instruction_encoding)),
        };
    }

    fn compute_dst_addr(&self, instruction: Instruction) -> Result<BigUint, VirtualMachineError> {
        let base_addr = match instruction.dst_register {
            Register.AP => Some(self.ap),
            Register.FP => Some(self.fp),
            _ => None,
        };
        if let Some(addr) = base_addr {
            Ok((addr + instruction.off0) % self.prime);
        }
        else{
            Err(VirtualMachineError::InvalidDstRegError);
        }
    }

    fn compute_op0_addr(&self, instruction: Instruction) -> Result<BigUint, VirtualMachineError> {
        let base_addr = match instruction.op0_register {
            Register.AP => Some(self.ap),
            Register.FP => Some(self.fp),
            _ => None,
        }
        if let Some(addr) = base_addr {
            Ok((addr + instruction.off1) % self.prime);
        }
        else{
            Err(VirtualMachineError::InvalidOp0RegError);
        }
    }

    fn compute_op1_addr(&self, instruction: Instruction, op0: Option<MaybeRelocatable>) -> Result<BigUint, VirtualMachineError> {
        let base_addr : Option<MaybeRelocatable>
        match instruction.op1_addr {
            Instruction.Op1Addr.FP => base_addr = Some(self.fp),
            Instruction.Op1Addr.AP => base_addr = Some(self.ap),
            Instruction.Op1Addr.IMM => {
                match instruction.off2{
                    1 => base_addr = Some(self.pc),
                    _ => Err(VirtualMachineError::ImmShouldBe1Error),
                },
            _ => None,
        };
        if let Some(addr) = base_addr {
            Ok((addr + instruction.off1) % self.prime);
        }
        else{
            Err(VirtualMachineError::InvalidOp1RegError);
        }
    }

}
#[derive(Debug, Clone)]
enum VirtualMachineError{
    InvalidInstructionEncodingError(MaybeRelocatable),
    InvalidDstRegError,
    InvalidOp0RegError,
    InvalidOp1RegError,
    ImmShouldBe1Error,
    UnknownOp0Error,
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VirtualMachineError::InvalidInstructionEcodingError(arg) => write!(f, "Instruction should be an int. Found: {}", arg),
            VirtualMachineError::InvalidDstRegError => write!(f,"Invalid dst_register value"),
            VirtualMachineError::InvalidOp0RegError => write!(f,"Invalid op0_register value"),
            VirtualMachineError::InvalidOp1RegError => write!(f,"Invalid op1_register value"),
            VirtualMachineError::ImmShouldBe1Error => write!(f,"In immediate mode, off2 should be 1"),
            VirtualMachineError::UnknownOp0Error => write!(f,"op0 must be known in double dereference"),
        };
    }
}

mod relocatable;
mod memory_dict;
mod validated_memory_dict;
mod trace_entry;
mod builtin_runner;
mod instruction;

//Import div_mod 
use::maybe_relocatable::MaybeRelocatable;
use::memory_dict::MemoryDict;
use::validated_memory_dict::ValidatedMemoryDict;
use::relocatable::MaybeRelocatable;
use::trace_entry::TraceEntry;
use::builtin_runner::BuitinRunner;
use::instruction::Instruction;
use num_bigint::BigUint;
use std::collections::HashMap;

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
    hint_pc_and_index: HashMap<i64, (MaybeRelocatable, i64)>,
    static_locals: Option<HashMap<..., ...>>,
    intruction_debug_info: HashMap<MaybeRelocatable, InstructionLocation>,
    debug_file_contents: HashMap<String, String>,
    error_message_attributes: Vec<VmAttributeScope>,
    program: ProgramBase,
    program_base: Option<MaybeRelocatable>,
    validated_memory: ValidatedMemoryDict,
    auto_deduction: HashMap<i64, Vec<(Rule, ())>>,
    accessesed_addresses: Vec<MaybeRelocatable>,
    trace: Vec<TraceEntry>,
    current_step: BigUint,
    skip_instruction_execution: bool
}

impl RunContext {
    ///Returns the encoded instruction (the value at pc) and the immediate value (the value atpc + 1, if it exists in the memory).
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
            Register::AP => Some(self.ap),
            Register::FP => Some(self.fp),
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
            Register::AP => Some(self.ap),
            Register::FP => Some(self.fp),
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
        let base_addr : Option<MaybeRelocatable>;
        match instruction.op1_addr {
            Instruction.Op1Addr::FP => base_addr = Some(self.fp),
            Instruction.Op1Addr::AP => base_addr = Some(self.ap),
            Instruction.Op1Addr::IMM => {
                match instruction.off2{
                    1 => base_addr = Some(self.pc),
                    _ => Err(VirtualMachineError::ImmShouldBe1Error),
                };
            },
            Instruction.Op1Addr::OP0 => {
                match op0 {
                    Some(addr) => base_addr = Some(addr),
                    None => Err(VirtualMachineError::UnknownOp0Error),
                };
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

impl VirtualMachine {
    fn update_fp(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        let new_fp = match instruction.fp_update {
            Instruction.FpUpdate::AP_PLUS2 => Some(self.run_context.ap + 2),
            Instruction.FpUpdate::DST => Some(operands.dst),
            Instruction.FpUpdate::REGULAR => Some(self.run_context.fp),
            _ => None,
        };
        match new_fp {
            Some(fp) => {
                self.run_context.fp = fp;
                Ok();
            },
            None => Err(VirtualMachineError::InvalidFpUpdateError),
        };     
    }

    fn update_ap(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        let new_ap = MaybeRelocatable;
        match instruction.ap_update {
            Instruction.ApUpdate::ADD => {
                match operands.res {
                    Some(res) => new_ap = self.run_context.ap + (res % self.prime),
                    None => Err(VirtualMachineError::UnconstrainedResAddError),
                };
            },
            Instruction.ApUpdate::ADD1 => new_ap = self.run_context.ap + 1,
            Instruction.ApUpdate::ADD2 => new_ap = self.run_context.ap + 2,
            Instruction.ApUpdate::REGULAR => new_ap = self.run_context.ap,
            _ => Err(VirtualMachineError::InvalidApUpdateError),
        };
        self.run_context.ap = new_ap % self.prime;
        Ok();
    }

    fn update_pc(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        let new_pc : Option<MaybeRelocatable>;
        match instruction.pc_update {
            Instruction.PcUpdate::REGULAR => new_pc = self.run_context.pc + size(instruction),
            Instruction.PcUpdate::JUMP => {
                match operands.res {
                    Some(res) => new_pc = res,
                    None => Err(VirtualMachineError::UnconstrainedResJumpError),
                };
            },
            Instruction.PcUpdate::JUMP_REL => {
                match operands.res {
                    Some(res) => {
                        match res {
                            MaybeRelocatable::Int(num_res) => new_pc = self.run_context.pc + num_res,
                            _ => Err(PureValueError("jmp rel", res)),
                        };
                    },
                    None => Err(UnconstrainedResJumpRelError),
                };
            },
            Instruction.PcUpdate::JNZ => {
                if self.is_zero(operands.res)? {
                    new_pc = self.run_context.pc + size(instruction);
                }
                else {
                    new_pc = self.run_context + operands.op1
                }
            },
            _ => Err(VirtualMachineError::InvalidPcUpdateError),
        };
        self.run_context.pc = new_pc % self.prime;
        Ok();
    }

    fn update_registers(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        self.update_fp(instruction, operands)?;
        self.update_ap(instruction, operands)?;
        self.update_pc(instruction, operands)?;
        Ok();
    }

    /// Returns true if the value is zero
    /// Used for JNZ instructions
    fn is_zero(value: MaybeRelocatable) -> Result<bool, VirtualMachineError> {
        match value {
            MaybeRelocatable::Int(num) => return num == 0,
            MaybeRelocatable::RelocatableValue => {
                if value.offset >= 0 {
                    return false;
                }
                else {
                    Err(VirtualMachineError::PureValueError("jmp != 0", value);
                }
            },
        };
    }

    ///Returns a tuple (deduced_op0, deduced_res).
    ///Deduces the value of op0 if possible (based on dst and op1). Otherwise, returns None.
    ///If res was already deduced, returns its deduced value as well.
    fn deduce_op0(&self, instruction: Instruction, dst: Option<MaybeRelocatable>, op1: Option<MaybeRelocatable>) 
        -> (Option<MaybeRelocatable>, Option<MaybeRelocatable>) {
            match instruction.opcode {
                Instruction.Opcode::CALL => return (Some(self.run_context.pc + size(instruction)), None),
                Instruction.Opcode::ASSERT_EQ => {
                    match instruction.res {
                        Instruction.Res::ADD => {
                            if let (Some(dst_addr), Some(op1_addr)) = (dst, op1) {
                                return (Some((dst_addr - op1_addr) % self.prime), Some(dst_addr));
                            }                            
                        },
                        Instruction.Res::MUL => { 
                            if let (Some(dst_addr), Some(op1_addr)) = (dst, op1) {
                                if let  (MaybeRelocatable::Int(num_dst), MaybeRelocatable::Int(num_op1)) = (dst_addr, op1_addr) {
                                    if num_op1 != 0 {
                                        return (Some(div_mod(num_dst, num_op1, self.prime)), Some(dst));
                                    }
                                }
                            }
                        },
                        _ => (),
                    };
                },
                _ => (),
            };
            return (None, None);
        }

        /// Returns a tuple (deduced_op1, deduced_res).
        ///Deduces the value of op1 if possible (based on dst and op0). Otherwise, returns None.
        ///If res was already deduced, returns its deduced value as well.
        fn deduce_op1(&self, instruction: Instruction, dst: Option<MaybeRelocatable>, op0: Option<MaybeRelocatable>) 
            -> (Option<MaybeRelocatable>, Option<MaybeRelocatable>) {
            match instruction.opcode {
                Instruction.Opcode::ASSERT_EQ => {
                    match instruction.res {
                        Instruction.Res::OP1 => {
                            if let Some(dst_addr) = dst {
                                return (dst, dst);
                            }
                        },
                        Instruction.Res::ADD => {
                            if let (Some(dst_addr), Some(op0_addr)) = (dst, op0) {
                                return (Some((dst_addr - op0_addr) % self.prime), dst);
                            }
                        },
                        Instruction.Res::MUL => {
                            if let (Some(dst_addr), Some(op0_addr)) = (dst, op0) {
                                if let  (MaybeRelocatable::Int(num_dst), MaybeRelocatable::Int(num_op0)) = (dst_addr, op0_addr) {
                                    if num_op0 != 0 {
                                        return (Some(div_mod(num_dst, num_op0, self.prime)), Some(dst));
                                    }
                                }
                            }
                        },
                        _ => (),
                    };
                },
                _ => (),
            };
            return (None, None);
        }

        ///Computes the value of res if possible
        fn compute_res(&self, instruction: Instruction, op0: MaybeRelocatable, op1: MaybeRelocatable) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
            match instruction.res {
                Instruction.Res::OP1 => Ok(Some(op1)),
                Instruction.Res::ADD => Ok(Some((op0 + op1) % self.prime)),
                Instruction.Res::MUL => {
                    if let (MaybeRelocatable::Int(num_op0), MaybeRelocatable::Int(num_op1)) = (op0, op1) {
                        Ok(Some((num_op0 * num_op1) % self.prime));
                    }
                    Err(VirtualMachineError::PureValueError("*", op0, op1));
                },
                Instruction.Res::UNCONSTRAINED => Ok(None),
                _ => Err(VirtualMachineError::InvalidResError),
            };
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
    InvalidFpUpdateError,
    InvalidApUpdateError,
    InvalidPcUpdateError,
    UnconstrainedResAddError,
    UnconstrainedResJumpError,
    UnconstrainedResJumpRelError,
    PureValueError(str, ())
    InvalidResError
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VirtualMachineError::InvalidInstructionEcodingError(arg) => write!(f, "Instruction should be an int. Found: {}", arg),
            VirtualMachineError::InvalidDstRegError => write!(f, "Invalid dst_register value"),
            VirtualMachineError::InvalidOp0RegError => write!(f, "Invalid op0_register value"),
            VirtualMachineError::InvalidOp1RegError => write!(f, "Invalid op1_register value"),
            VirtualMachineError::ImmShouldBe1Error => write!(f, "In immediate mode, off2 should be 1"),
            VirtualMachineError::UnknownOp0Error => write!(f, "op0 must be known in double dereference"),
            VirtualMachineError::InvalidFpUpdateError => write!(f, "Invalid fp_update value"),
            VirtualMachineError::InvalidApUpdateError => write!(f, "Invalid ap_update value"),
            VirtualMachineError::InvalidPcUpdateError => write!(f, "Invalid pc_update value"),
            VirtualMachineError::UnconstrainedResAddError => write!(f, "Res.UNCONSTRAINED cannot be used with ApUpdate.ADD")
            VirtualMachineError::UnconstrainedJumpAddError => write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP")
            VirtualMachineError::UnconstrainedResJumpRelError => write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP_REL")
            VirtualMachineError::InvalidResError => write!(f, "Invalid res value")
            //TODO: add PureValueError
        };
    }
}

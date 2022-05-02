use crate::vm::memory_dict::Memory;
use crate::vm::validated_memory_dict::ValidatedMemoryDict;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::trace_entry::TraceEntry;
use crate::compiler::instruction::Instruction;
use crate::compiler::instruction::FpUpdate;
use crate::compiler::instruction::ApUpdate;
use crate::compiler::instruction::PcUpdate;
use crate::compiler::instruction::Opcode;
use crate::compiler::instruction::Res;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use super::run_context::RunContext;
use std::fmt;
use std::collections::HashMap;

macro_rules! bigint {
    ($val : expr) => {
        BigInt::from_i64($val).unwrap()
    }
}

struct Operands {
    dst: MaybeRelocatable,
    res: Option<MaybeRelocatable>,
    op0: MaybeRelocatable,
    op1: MaybeRelocatable
}

pub struct VirtualMachine {
    run_context: RunContext,
    prime: BigInt,
    //builtin_runners: Option<HashMap<String, BuiltinRunner>>,
    //exec_scopes: Vec<HashMap<..., ...>>,
    //enter_scope: ,
    //hints: HashMap<MaybeRelocatable, Vec<CompiledHint>>,
    //hint_locals: HashMap<..., ...>,
    //hint_pc_and_index: HashMap<i64, (MaybeRelocatable, i64)>,
    //static_locals: Option<HashMap<..., ...>>,
    //intruction_debug_info: HashMap<MaybeRelocatable, InstructionLocation>,
    //debug_file_contents: HashMap<String, String>,
    //error_message_attributes: Vec<VmAttributeScope>,
    //program: ProgramBase,
    program_base: Option<MaybeRelocatable>,
    validated_memory: ValidatedMemoryDict,
    //auto_deduction: HashMap<i64, Vec<(Rule, ())>>,
    accessesed_addresses: Vec<MaybeRelocatable>,
    trace: Vec<TraceEntry>,
    current_step: BigInt,
    skip_instruction_execution: bool
}

impl VirtualMachine {
    fn update_fp(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        let new_fp = match instruction.fp_update {
            FpUpdate::AP_PLUS2 => Some((self.run_context.ap + bigint!(2))?),
            FpUpdate::DST => Some(operands.dst),
            FpUpdate::REGULAR => Some(self.run_context.fp),
            _ => None,
        };
        match new_fp {
            Some(fp) => {
                self.run_context.fp = fp;
                return Ok(());
            },
            None => return Err(VirtualMachineError::InvalidFpUpdateError),
        };     
    }

    fn update_ap(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        let new_ap : MaybeRelocatable;
        match instruction.ap_update {
            ApUpdate::ADD => {
                match operands.res {
                    Some(res) => new_ap = (self.run_context.ap + (res % self.prime))?,
                    None => return Err(VirtualMachineError::UnconstrainedResAddError),
                };
            },
            ApUpdate::ADD1 => new_ap = (self.run_context.ap + bigint!(1))?,
            ApUpdate::ADD2 => new_ap = (self.run_context.ap + bigint!(2))?,
            ApUpdate::REGULAR => new_ap = self.run_context.ap,
            _ => return Err(VirtualMachineError::InvalidApUpdateError),
        };
        self.run_context.ap = new_ap % self.prime;
        return Ok(());
    }

    fn update_pc(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        let new_pc : MaybeRelocatable;
        match instruction.pc_update {
            PcUpdate::REGULAR => new_pc = (self.run_context.pc + bigint!(Instruction::size(&instruction)))?,
            PcUpdate::JUMP => {
                match operands.res {
                    Some(res) => new_pc = res,
                    None => return Err(VirtualMachineError::UnconstrainedResJumpError),
                };
            },
            PcUpdate::JUMP_REL => {
                match operands.res {
                    Some(res) => {
                        match res {
                            MaybeRelocatable::Int(num_res) => new_pc = (self.run_context.pc + num_res)?,
                            _ => return Err(VirtualMachineError::PureValueError),
                        };
                    },
                    None => return Err(VirtualMachineError::UnconstrainedResJumpRelError),
                };
            },
            PcUpdate::JNZ => {
                if VirtualMachine::is_zero(operands.res)? {
                    new_pc = (self.run_context.pc + bigint!(Instruction::size(&instruction)))?;
                }
                else {
                    new_pc = (self.run_context.pc + operands.op1)?
                }
            },
            _ => return Err(VirtualMachineError::InvalidPcUpdateError),
        };
        self.run_context.pc = new_pc % self.prime;
        return Ok(());
    }


    fn update_registers(&mut self, instruction: Instruction, operands: Operands) -> Result<(), VirtualMachineError> {
        self.update_fp(instruction, operands)?;
        self.update_ap(instruction, operands)?;
        self.update_pc(instruction, operands)?;
        return Ok(());
    }

    /// Returns true if the value is zero
    /// Used for JNZ instructions
    fn is_zero(addr: Option<MaybeRelocatable>) -> Result<bool, VirtualMachineError> {
        if let Some(value) = addr {
            match value {
                MaybeRelocatable::Int(num) => return Ok(num == bigint!(0)),
                MaybeRelocatable::RelocatableValue(rel_value) => {
                    if rel_value.offset >= bigint!(0) {
                        return Ok(false);
                    }
                    else {
                        return Err(VirtualMachineError::PureValueError);
                    }
                },
            };
        }
        return Err(VirtualMachineError::NotImplementedError);
    }


    ///Returns a tuple (deduced_op0, deduced_res).
    ///Deduces the value of op0 if possible (based on dst and op1). Otherwise, returns None.
    ///If res was already deduced, returns its deduced value as well.
    fn deduce_op0(&self, instruction: Instruction, dst: Option<MaybeRelocatable>, op1: Option<MaybeRelocatable>) 
        -> Result<(Option<MaybeRelocatable>, Option<MaybeRelocatable>), VirtualMachineError> {
            match instruction.opcode {
                Opcode::CALL => return Ok((Some((self.run_context.pc + bigint!(Instruction::size(&instruction)))?), None)),
                Opcode::ASSERT_EQ => {
                    match instruction.res {
                        Res::ADD => {
                            if let (Some(dst_addr), Some(op1_addr)) = (dst, op1) {
                                return Ok((Some((dst_addr - op1_addr)? % self.prime), Some(dst_addr)));
                            }                            
                        },
                        Res::MUL => { 
                            if let (Some(dst_addr), Some(op1_addr)) = (dst, op1) {
                                if let  (MaybeRelocatable::Int(num_dst), MaybeRelocatable::Int(num_op1)) = (dst_addr, op1_addr) {
                                    if num_op1 != BigInt::from_i64(0).unwrap() {
                                        return Ok((Some(MaybeRelocatable::Int(num_dst / num_op1) % self.prime), dst));
                                    }
                                }
                            }
                        },
                        _ => (),
                    };
                },
                _ => (),
            };
            return Ok((None, None));
        }

        /// Returns a tuple (deduced_op1, deduced_res).
        ///Deduces the value of op1 if possible (based on dst and op0). Otherwise, returns None.
        ///If res was already deduced, returns its deduced value as well.
        fn deduce_op1(&self, instruction: Instruction, dst: Option<MaybeRelocatable>, op0: Option<MaybeRelocatable>) 
            -> Result<(Option<MaybeRelocatable>, Option<MaybeRelocatable>), VirtualMachineError> {
            match instruction.opcode {
                Opcode::ASSERT_EQ => {
                    match instruction.res {
                        Res::OP1 => {
                            if let Some(dst_addr) = dst {
                                return Ok((dst, dst));
                            }
                        },
                        Res::ADD => {
                            if let (Some(dst_addr), Some(op0_addr)) = (dst, op0) {
                                return Ok((Some((dst_addr - op0_addr)? % self.prime), dst));
                            }
                        },
                        Res::MUL => {
                            if let (Some(dst_addr), Some(op0_addr)) = (dst, op0) {
                                if let (MaybeRelocatable::Int(num_dst), MaybeRelocatable::Int(num_op0)) = (dst_addr, op0_addr) {
                                    if num_op0 != bigint!(0) {
                                        return Ok((Some(MaybeRelocatable::Int(num_dst / num_op0) % self.prime), dst));
                                    }
                                }
                            }
                        },
                        _ => (),
                    };
                },
                _ => (),
            };
            return Ok((None, None));
        }

        ///Computes the value of res if possible
        fn compute_res(&self, instruction: Instruction, op0: MaybeRelocatable, op1: MaybeRelocatable) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
            match instruction.res {
                Res::OP1 => return Ok(Some(op1)),
                Res::ADD => return Ok(Some((op0 + op1)? % self.prime)),
                Res::MUL => {
                    if let (MaybeRelocatable::Int(num_op0), MaybeRelocatable::Int(num_op1)) = (op0, op1) {
                        return Ok(Some(MaybeRelocatable::Int(num_op0 * num_op1) % self.prime));
                    }
                    return Err(VirtualMachineError::PureValueError);
                },
                Res::UNCONSTRAINED => return Ok(None),
                _ => return Err(VirtualMachineError::InvalidResError),
            };
        }

        fn deduce_dst(&self, instruction: Instruction, res: Option<MaybeRelocatable>) -> Option<MaybeRelocatable> {
            match instruction.opcode {
                Opcode::ASSERT_EQ => {
                    if let Some(res_addr) = res {
                        return res;
                    }
                },
                Opcode::CALL => return Some(self.run_context.fp),
                _ => (),
            };
            return None
        }
}


#[derive(Debug)]
pub enum VirtualMachineError{
    //InvalidInstructionEncodingError(MaybeRelocatable), Impl fmt for MaybeRelocatable
    InvalidInstructionEncodingError,
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
    PureValueError,
    InvalidResError,
    RelocatableAddError,
    NotImplementedError,
    DiffIndexSubError
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            //VirtualMachineError::InvalidInstructionEncodingError(arg) => write!(f, "Instruction should be an int. Found: {}", arg),
            VirtualMachineError::InvalidInstructionEncodingError => write!(f, "Instruction should be an int. Found:"),
            VirtualMachineError::InvalidDstRegError => write!(f, "Invalid dst_register value"),
            VirtualMachineError::InvalidOp0RegError => write!(f, "Invalid op0_register value"),
            VirtualMachineError::InvalidOp1RegError => write!(f, "Invalid op1_register value"),
            VirtualMachineError::ImmShouldBe1Error => write!(f, "In immediate mode, off2 should be 1"),
            VirtualMachineError::UnknownOp0Error => write!(f, "op0 must be known in double dereference"),
            VirtualMachineError::InvalidFpUpdateError => write!(f, "Invalid fp_update value"),
            VirtualMachineError::InvalidApUpdateError => write!(f, "Invalid ap_update value"),
            VirtualMachineError::InvalidPcUpdateError => write!(f, "Invalid pc_update value"),
            VirtualMachineError::UnconstrainedResAddError => write!(f, "Res.UNCONSTRAINED cannot be used with ApUpdate.ADD"),
            VirtualMachineError::UnconstrainedResJumpError => write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP"),
            VirtualMachineError::UnconstrainedResJumpRelError => write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP_REL"),
            VirtualMachineError::InvalidResError => write!(f, "Invalid res value"),
            VirtualMachineError::RelocatableAddError => write!(f, "Cannot add two relocatable values"),
            VirtualMachineError::NotImplementedError => write!(f, "This is not implemented"),
            VirtualMachineError::PureValueError => Ok(()), //TODO
            VirtualMachineError::DiffIndexSubError => write!(f, "Can only subtract two relocatable values of the same segment"),
        } 
    }
}


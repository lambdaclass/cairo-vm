use crate::vm::instruction::{ApUpdate, FpUpdate, Instruction, Opcode, PcUpdate, Res};
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::run_context::RunContext;
use crate::vm::trace_entry::TraceEntry;
use crate::vm::validated_memory_dict::ValidatedMemoryDict;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::fmt;

macro_rules! bigint {
    ($val : expr) => {
        BigInt::from_i32($val).unwrap()
    };
}

struct Operands {
    dst: MaybeRelocatable,
    res: Option<MaybeRelocatable>,
    op0: MaybeRelocatable,
    op1: MaybeRelocatable,
}

struct Rule {
    func: fn(&VirtualMachine, &MaybeRelocatable, &()) -> Option<MaybeRelocatable>,
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
    auto_deduction: HashMap<BigInt, Vec<(Rule, ())>>,
    accessesed_addresses: Vec<MaybeRelocatable>,
    trace: Vec<TraceEntry>,
    current_step: BigInt,
    skip_instruction_execution: bool,
}

impl VirtualMachine {
    fn update_fp(
        &mut self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        let new_fp = match instruction.fp_update {
            FpUpdate::AP_PLUS2 => Some(self.run_context.ap.add_num_addr(bigint!(2), None)),
            FpUpdate::DST => Some(operands.dst.clone()),
            FpUpdate::REGULAR => return Ok(()),
        };
        match new_fp {
            Some(fp) => {
                self.run_context.fp = fp;
                return Ok(());
            }
            None => return Err(VirtualMachineError::InvalidFpUpdateError),
        };
    }

    fn update_ap(
        &mut self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        let new_ap: Option<MaybeRelocatable> = match instruction.ap_update {
            ApUpdate::ADD => match operands.res.clone() {
                Some(res) => Some(
                    self.run_context
                        .ap
                        .add_addr(res, Some(self.prime.clone()))?,
                ),
                None => return Err(VirtualMachineError::UnconstrainedResAddError),
            },
            ApUpdate::ADD1 => Some(self.run_context.ap.add_num_addr(bigint!(1), None)),
            ApUpdate::ADD2 => Some(self.run_context.ap.add_num_addr(bigint!(2), None)),
            ApUpdate::REGULAR => return Ok(()),
        };
        if let Some(ap) = new_ap {
            self.run_context.ap = ap % self.prime.clone();
            return Ok(());
        }
        return Err(VirtualMachineError::InvalidApUpdateError);
    }

    fn update_pc(
        &mut self,
        instruction: &Instruction,
        operands: &Operands,
    ) -> Result<(), VirtualMachineError> {
        let new_pc: MaybeRelocatable = match instruction.pc_update {
            PcUpdate::REGULAR => self
                .run_context
                .pc
                .add_num_addr(bigint!(Instruction::size(&instruction)), None),
            PcUpdate::JUMP => match operands.res.clone() {
                Some(res) => res,
                None => return Err(VirtualMachineError::UnconstrainedResJumpError),
            },
            PcUpdate::JUMP_REL => match operands.res.clone() {
                Some(res) => match res {
                    MaybeRelocatable::Int(num_res) => {
                        self.run_context.pc.add_num_addr(num_res, None)
                    }

                    _ => return Err(VirtualMachineError::PureValueError),
                },
                None => return Err(VirtualMachineError::UnconstrainedResJumpRelError),
            },
            PcUpdate::JNZ => match VirtualMachine::is_zero(operands.res.clone())? {
                true => self
                    .run_context
                    .pc
                    .add_num_addr(bigint!(Instruction::size(&instruction)), None),
                false => (self.run_context.pc.add_addr(operands.op1.clone(), None))?,
            },
        };
        self.run_context.pc = new_pc % self.prime.clone();
        return Ok(());
    }

    fn update_registers(
        &mut self,
        instruction: Instruction,
        operands: Operands,
    ) -> Result<(), VirtualMachineError> {
        self.update_fp(&instruction, &operands)?;
        self.update_ap(&instruction, &operands)?;
        self.update_pc(&instruction, &operands)?;
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
                    } else {
                        return Err(VirtualMachineError::PureValueError);
                    }
                }
            };
        }
        return Err(VirtualMachineError::NotImplementedError);
    }

    ///Returns a tuple (deduced_op0, deduced_res).
    ///Deduces the value of op0 if possible (based on dst and op1). Otherwise, returns None.
    ///If res was already deduced, returns its deduced value as well.
    fn deduce_op0(
        &self,
        instruction: &Instruction,
        dst: Option<&MaybeRelocatable>,
        op1: Option<&MaybeRelocatable>,
    ) -> Result<(Option<MaybeRelocatable>, Option<MaybeRelocatable>), VirtualMachineError> {
        match instruction.opcode {
            Opcode::CALL => {
                return Ok((
                    Some(
                        self.run_context
                            .pc
                            .add_num_addr(bigint!(Instruction::size(&instruction)), None),
                    ),
                    None,
                ))
            }
            Opcode::ASSERT_EQ => {
                match instruction.res {
                    Res::ADD => {
                        if let (Some(dst_addr), Some(op1_addr)) = (dst, op1) {
                            return Ok((
                                Some((dst_addr.sub_addr(op1_addr))? % self.prime.clone()),
                                Some(dst_addr.clone()),
                            ));
                        }
                    }
                    Res::MUL => {
                        if let (Some(dst_addr), Some(op1_addr)) = (dst, op1) {
                            if let (
                                MaybeRelocatable::Int(num_dst),
                                MaybeRelocatable::Int(ref num_op1_ref),
                            ) = (dst_addr, op1_addr)
                            {
                                let num_op1 = Clone::clone(num_op1_ref);
                                if num_op1 != bigint!(0) {
                                    return Ok((
                                        Some(
                                            MaybeRelocatable::Int(num_dst / num_op1)
                                                % self.prime.clone(),
                                        ),
                                        Some(dst_addr.clone()),
                                    ));
                                }
                            }
                        }
                    }
                    _ => (),
                };
            }
            _ => (),
        };
        return Ok((None, None));
    }

    /// Returns a tuple (deduced_op1, deduced_res).
    ///Deduces the value of op1 if possible (based on dst and op0). Otherwise, returns None.
    ///If res was already deduced, returns its deduced value as well.
    fn deduce_op1(
        &self,
        instruction: &Instruction,
        dst: Option<&MaybeRelocatable>,
        op0: Option<MaybeRelocatable>,
    ) -> Result<(Option<MaybeRelocatable>, Option<MaybeRelocatable>), VirtualMachineError> {
        if let Opcode::ASSERT_EQ = instruction.opcode {
            match instruction.res {
                Res::OP1 => {
                    if let Some(dst_addr) = dst {
                        return Ok((Some(dst_addr.clone()), Some(dst_addr.clone())));
                    }
                }
                Res::ADD => {
                    if let (Some(dst_addr), Some(op0_addr)) = (dst, op0) {
                        return Ok((
                            Some((dst_addr.sub_addr(&op0_addr))?),
                            Some(dst_addr.clone()),
                        ));
                    }
                }
                Res::MUL => {
                    if let (Some(dst_addr), Some(op0_addr)) = (dst, op0) {
                        if let (MaybeRelocatable::Int(num_dst), MaybeRelocatable::Int(num_op0)) =
                            (dst_addr, op0_addr)
                        {
                            if num_op0 != bigint!(0) {
                                return Ok((
                                    Some(
                                        MaybeRelocatable::Int(num_dst / num_op0)
                                            % self.prime.clone(),
                                    ),
                                    Some(dst_addr.clone()),
                                ));
                            }
                        }
                    }
                }
                _ => (),
            };
        };
        return Ok((None, None));
    }

    ///Computes the value of res if possible
    fn compute_res(
        &self,
        instruction: &Instruction,
        op0: &MaybeRelocatable,
        op1: &MaybeRelocatable,
    ) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
        match instruction.res {
            Res::OP1 => return Ok(Some(op1.clone())),
            Res::ADD => return Ok(Some(op0.add_addr(op0.clone(), Some(self.prime.clone()))?)),
            Res::MUL => {
                if let (MaybeRelocatable::Int(num_op0), MaybeRelocatable::Int(num_op1)) = (op0, op1)
                {
                    return Ok(Some(
                        MaybeRelocatable::Int(num_op0 * num_op1) % self.prime.clone(),
                    ));
                }
                return Err(VirtualMachineError::PureValueError);
            }
            Res::UNCONSTRAINED => return Ok(None),
        };
    }

    fn deduce_dst(
        &self,
        instruction: &Instruction,
        res: Option<&MaybeRelocatable>,
    ) -> Option<MaybeRelocatable> {
        match instruction.opcode {
            Opcode::ASSERT_EQ => {
                if let Some(res_addr) = res {
                    return Some(res_addr.clone());
                }
            }
            Opcode::CALL => return Some(self.run_context.fp.clone()),
            _ => (),
        };
        return None;
    }

    fn opcode_assertions(&self, instruction: &Instruction, operands: &Operands) {
        match instruction.opcode {
            Opcode::ASSERT_EQ => {
                match &operands.res {
                    None => panic!("Res.UNCONSTRAINED cannot be used with Opcode.ASSERT_EQ"),
                    Some(res) => {
                        if let (MaybeRelocatable::Int(res_num), MaybeRelocatable::Int(dst_num)) =
                            (res, &operands.dst)
                        {
                            if res_num != dst_num {
                                panic!(
                                    "An ASSERT_EQ instruction failed: {} != {}",
                                    res_num, dst_num
                                );
                            };
                        };
                    }
                };
            }
            Opcode::CALL => {
                if let (MaybeRelocatable::Int(op0_num), MaybeRelocatable::Int(run_pc)) =
                    (&operands.op0, &self.run_context.pc)
                {
                    let return_pc = run_pc + bigint!(instruction.size());
                    if op0_num != &return_pc {
                        panic!("Call failed to write return-pc (inconsistent op0): {} != {}. Did you forget to increment ap?", op0_num, return_pc);
                    };
                };

                if let (MaybeRelocatable::Int(return_fp), MaybeRelocatable::Int(dst_num)) =
                    (&self.run_context.fp, &operands.dst)
                {
                    if dst_num != return_fp {
                        panic!("Call failed to write return-fp (inconsistent dst): fp->{} != dst->{}. Did you forget to increment ap?",dst_num,dst_num);
                    };
                };
            }
            _ => {}
        }
    }

    pub fn deduce_memory_cell(&mut self, addr: MaybeRelocatable) -> Option<&MaybeRelocatable> {
        match addr {
            MaybeRelocatable::Int(_) => (),
            MaybeRelocatable::RelocatableValue(ref addr_val) => {
                match self.auto_deduction.get(&addr_val.segment_index) {
                    Some(rules) => {
                        for (rule, args) in rules.iter() {
                            match (rule.func)(self, &addr, args) {
                                Some(value) => {
                                    self.validated_memory.memory.insert(&addr, &value);
                                    return self.validated_memory.memory.get(&addr);
                                }
                                None => (),
                            };
                        }
                    }
                    None => (),
                };
            }
        }
        None
    }

    pub fn compute_operands(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(Operands, Vec<MaybeRelocatable>), VirtualMachineError> {
        let dst_addr: MaybeRelocatable = self.run_context.compute_dst_addr(instruction);
        let mut dst: Option<&MaybeRelocatable> = self.validated_memory.memory.get(&dst_addr);
        let op0_addr: MaybeRelocatable = self.run_context.compute_op0_addr(instruction);
        let mut op0: Option<&MaybeRelocatable> = self.validated_memory.memory.get(&op0_addr);
        let op1_addr: MaybeRelocatable = self
            .run_context
            .compute_op1_addr(instruction, op0.clone())?;
        let mut op1: Option<&MaybeRelocatable> = self.validated_memory.memory.get(&op1_addr);
        let mut res: Option<MaybeRelocatable> = None;
        
        if matches!(op0, None) {
            op0 = self.deduce_memory_cell(op0_addr);
        }/*
        if matches!(op1, None) {
            op1 = self.deduce_memory_cell(op1_addr).as_ref();
        }

        let should_update_dst = matches!(dst, None);
        let should_update_op0 = matches!(op0, None);
        let should_update_op1 = matches!(op1, None);

        if matches!(op0, None) {
            let deduced_operand = self.deduce_op0(instruction, dst, op1).unwrap();
            op0 = deduced_operand.0.as_ref();
            let deduced_res = deduced_operand.1;
            if matches!(res, None) {
                res = deduced_res
            }
        }
        if matches!(op1, None) {
            let deduced_operand = self.deduce_op1(instruction, dst, Some(op0.unwrap().clone())).unwrap();
            op1 = deduced_operand.0.as_ref();
            let deduced_res = deduced_operand.1;
            if matches!(res, None) {
                res = deduced_res
            }
        }

        if matches!(op0, None) {
            op0 = self.validated_memory.memory.get(&op0_addr);
        }
        if matches!(op1, None) {
            op1 = self.validated_memory.memory.get(&op1_addr);
        }

        if matches!(res, None) {
            res = self
                .compute_res(instruction, &op0.unwrap(), &op1.unwrap())
                .unwrap();
        }

        if matches!(dst, None) {
            match instruction.opcode {
                Opcode::ASSERT_EQ if matches!(res, Some(_)) => dst = res.as_ref(),
                Opcode::CALL => dst = Some(&self.run_context.fp),
                _ => (),
            }
        }

        if matches!(dst, None) {
            dst = self.validated_memory.memory.get(&dst_addr)
        }

        if should_update_dst {
            self.validated_memory
                .memory
                .insert(&dst_addr, &dst.unwrap());
        }
        if should_update_op0 {
            self.validated_memory
                .memory
                .insert(&op0_addr, &op0.unwrap());
        }
        if should_update_op1 {
            self.validated_memory
                .memory
                .insert(&op1_addr, &op1.unwrap());
        }
        (
            Operands { dst:dst.unwrap().clone(), op0:op0.unwrap().clone(), op1:op1.unwrap().clone(), res },
            [dst_addr, op0_addr, op1_addr].to_vec(),
        )
        */
        Ok((
            Operands {
                dst: dst.unwrap().clone(),
                op0: op0.unwrap().clone(),
                op1: op1.unwrap().clone(),
                res,
            },
            [].to_vec(),
        ))
    }
}

#[derive(Debug, PartialEq)]
pub enum VirtualMachineError {
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
    DiffIndexSubError,
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            //VirtualMachineError::InvalidInstructionEncodingError(arg) => write!(f, "Instruction should be an int. Found: {}", arg),
            VirtualMachineError::InvalidInstructionEncodingError => {
                write!(f, "Instruction should be an int. Found:")
            }
            VirtualMachineError::InvalidDstRegError => write!(f, "Invalid dst_register value"),
            VirtualMachineError::InvalidOp0RegError => write!(f, "Invalid op0_register value"),
            VirtualMachineError::InvalidOp1RegError => write!(f, "Invalid op1_register value"),
            VirtualMachineError::ImmShouldBe1Error => {
                write!(f, "In immediate mode, off2 should be 1")
            }
            VirtualMachineError::UnknownOp0Error => {
                write!(f, "op0 must be known in double dereference")
            }
            VirtualMachineError::InvalidFpUpdateError => write!(f, "Invalid fp_update value"),
            VirtualMachineError::InvalidApUpdateError => write!(f, "Invalid ap_update value"),
            VirtualMachineError::InvalidPcUpdateError => write!(f, "Invalid pc_update value"),
            VirtualMachineError::UnconstrainedResAddError => {
                write!(f, "Res.UNCONSTRAINED cannot be used with ApUpdate.ADD")
            }
            VirtualMachineError::UnconstrainedResJumpError => {
                write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP")
            }
            VirtualMachineError::UnconstrainedResJumpRelError => {
                write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP_REL")
            }
            VirtualMachineError::InvalidResError => write!(f, "Invalid res value"),
            VirtualMachineError::RelocatableAddError => {
                write!(f, "Cannot add two relocatable values")
            }
            VirtualMachineError::NotImplementedError => write!(f, "This is not implemented"),
            VirtualMachineError::PureValueError => Ok(()), //TODO
            VirtualMachineError::DiffIndexSubError => write!(
                f,
                "Can only subtract two relocatable values of the same segment"
            ),
        }
    }
}

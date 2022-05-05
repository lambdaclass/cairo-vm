use crate::vm::instruction::Instruction;
use crate::vm::instruction::Op1Addr;
use crate::vm::instruction::Register;
use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::vm_core::VirtualMachineError;
use num_bigint::BigInt;
use num_traits::cast::FromPrimitive;

pub struct RunContext {
    pub memory: Memory,
    pub pc: MaybeRelocatable,
    pub ap: MaybeRelocatable,
    pub fp: MaybeRelocatable,
    pub prime: BigInt,
}

impl RunContext {
    ///Returns the encoded instruction (the value at pc) and the immediate value (the value at pc + 1, if it exists in the memory).
    fn get_instruction_encoding(
        &self,
    ) -> Result<(&BigInt, Option<&MaybeRelocatable>), VirtualMachineError> {
        let encoding_ref: &BigInt;
        {
            if let Some(&MaybeRelocatable::Int(ref encoding)) = self.memory.get(&self.pc) {
                encoding_ref = encoding;
            } else {
                return Err(VirtualMachineError::InvalidInstructionEncodingError);
            }
            let imm_addr = self.pc.add_num_addr(BigInt::from_i32(1).unwrap(),Some(self.prime.clone()));
            let optional_imm = self.memory.get(&imm_addr);
            return Ok((encoding_ref, optional_imm));
        };
    }

    pub fn compute_dst_addr(
        &self,
        instruction: &Instruction,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.dst_register {
            Register::AP => Some(&self.ap),
            Register::FP => Some(&self.fp),
        };
        match base_addr {
            Some(addr) => {
                return Ok(addr.add_num_addr(instruction.off0.clone(), Some(self.prime.clone())))
            }
            _ => return Err(VirtualMachineError::InvalidDstRegError),
        };
    }

    pub fn compute_op0_addr(
        &self,
        instruction: &Instruction,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.op0_register {
            Register::AP => Some(&self.ap),
            Register::FP => Some(&self.fp),
        };
        if let Some(addr) = base_addr {
            return Ok(addr.add_num_addr(instruction.off1.clone(), Some(self.prime.clone())));
        } else {
            return Err(VirtualMachineError::InvalidOp0RegError);
        }
    }

    pub fn compute_op1_addr(
        &self,
        instruction: &Instruction,
        op0: Option<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr: Option<&MaybeRelocatable>;
        match instruction.op1_addr {
            Op1Addr::FP => base_addr = Some(&self.fp),
            Op1Addr::AP => base_addr = Some(&self.ap),
            Op1Addr::IMM => {
                if instruction.off2 == BigInt::from_i32(1).unwrap() {
                    base_addr = Some(&self.pc);
                }
                return Err(VirtualMachineError::ImmShouldBe1Error);
            }
            Op1Addr::OP0 => {
                match op0 {
                    Some(addr) => {
                        return Ok((addr + instruction.off1.clone())? % self.prime.clone())
                    }
                    None => return Err(VirtualMachineError::UnknownOp0Error),
                };
            }
        }
        if let Some(addr) = base_addr {
            return Ok(addr.add_num_addr(instruction.off1.clone(), Some(self.prime.clone())));
        } else {
            return Err(VirtualMachineError::InvalidOp1RegError);
        }
    }
}

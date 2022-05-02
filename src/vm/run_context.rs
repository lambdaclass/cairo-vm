use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::vm_core::VirtualMachineError;
use num_bigint::BigInt;
use crate::compiler::instruction::Instruction;
use crate::compiler::instruction::Register;
use crate::compiler::instruction::Op1Addr;
use crate::vm::memory_dict::Memory;
use num_traits::cast::FromPrimitive;

pub struct RunContext {
    pub memory: Memory,
    pub pc: MaybeRelocatable,
    pub ap: MaybeRelocatable,
    pub fp: MaybeRelocatable,
    pub prime: BigInt
}

impl RunContext {
    ///Returns the encoded instruction (the value at pc) and the immediate value (the value at pc + 1, if it exists in the memory).
    fn get_instruction_encoding(&self) -> Result<(BigInt, Option<MaybeRelocatable>), VirtualMachineError> {
        let instruction_encoding = self.memory[self.pc];
        match instruction_encoding{
            MaybeRelocatable::Int(encoding) => {
                let imm_addr = (self.pc + BigInt::from_i64(1).unwrap())? % self.prime;
                let optional_imm = self.memory.get(&imm_addr);
                return Ok((encoding, optional_imm));
            },
            _ => return  Err(VirtualMachineError::InvalidInstructionEncodingError),
        };
    }

    fn compute_dst_addr(&self, instruction: Instruction) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.dst_register {
            Register::AP => Some(self.ap),
            Register::FP => Some(self.fp),
            _ => None,
        };
        if let Some(addr) = base_addr {
            return Ok((addr + instruction.off0)? % self.prime);
        }
        else{
            return Err(VirtualMachineError::InvalidDstRegError);
        }
    }

    fn compute_op0_addr(&self, instruction: Instruction) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.op0_register {
            Register::AP => Some(self.ap),
            Register::FP => Some(self.fp),
            _ => None,
        };
        if let Some(addr) = base_addr {
            return Ok((addr + instruction.off1)? % self.prime);
        }
        else{
            return Err(VirtualMachineError::InvalidOp0RegError);
        }
    }

    fn compute_op1_addr(&self, instruction: Instruction, op0: Option<MaybeRelocatable>) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr : Option<MaybeRelocatable>;
        match instruction.op1_addr {
            Op1Addr::FP => base_addr = Some(self.fp),
            Op1Addr::AP => base_addr = Some(self.ap),
            Op1Addr::IMM => {
                let one = BigInt::from_i64(1);
                match instruction.off2{
                    one => base_addr = Some(self.pc),
                    _ => return Err(VirtualMachineError::ImmShouldBe1Error),
                };
            },
            Op1Addr::OP0 => {
                match op0 {
                    Some(addr) => base_addr = Some(addr),
                    None => return Err(VirtualMachineError::UnknownOp0Error),
                };
            },
            _ => (),
        }
        if let Some(addr) = base_addr {
            return Ok((addr + instruction.off1)? % self.prime);
        }
        else {
            return Err(VirtualMachineError::InvalidOp1RegError);
        }
    }

}


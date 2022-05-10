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
            let imm_addr = self
                .pc
                .add_num_addr(BigInt::from_i32(1).unwrap(), Some(self.prime.clone()));
            let optional_imm = self.memory.get(&imm_addr);
            return Ok((encoding_ref, optional_imm));
        };
    }

    pub fn compute_dst_addr(&self, instruction: &Instruction) -> MaybeRelocatable {
        let base_addr = match instruction.dst_register {
            Register::AP => &self.ap,
            Register::FP => &self.fp,
        };
        return base_addr.add_num_addr(instruction.off0.clone(), Some(self.prime.clone()));
    }

    pub fn compute_op0_addr(&self, instruction: &Instruction) -> MaybeRelocatable {
        let base_addr = match instruction.op0_register {
            Register::AP => &self.ap,
            Register::FP => &self.fp,
        };
        return base_addr.add_num_addr(instruction.off1.clone(), Some(self.prime.clone()));
    }

    pub fn compute_op1_addr(
        &self,
        instruction: &Instruction,
        op0: Option<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.op1_addr {
            Op1Addr::FP => &self.fp,
            Op1Addr::AP => &self.ap,
            Op1Addr::IMM => match instruction.off2 == BigInt::from_i32(1).unwrap() {
                true => &self.pc,
                false => return Err(VirtualMachineError::ImmShouldBe1Error),
            },
            Op1Addr::OP0 => match op0 {
                Some(addr) => return Ok(addr + instruction.off1.clone() % self.prime.clone()),
                None => return Err(VirtualMachineError::UnknownOp0Error),
            },
        };
        return Ok(base_addr.add_num_addr(instruction.off1.clone(), Some(self.prime.clone())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::instruction::{ApUpdate, FpUpdate, Opcode, PcUpdate, Res};
    use std::collections::HashMap;

    #[test]
    fn compute_dst_addr_for_ap_register() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::AP,
            op0_register: Register::FP,
            op1_addr: Op1Addr::AP,
            res: Res::ADD,
            pc_update: PcUpdate::REGULAR,
            ap_update: ApUpdate::REGULAR,
            fp_update: FpUpdate::REGULAR,
            opcode: Opcode::NOP,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let MaybeRelocatable::Int(num) = run_context.compute_dst_addr(&instruction) {
            assert_eq!(num, BigInt::from_i32(6).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_dst_addr_for_fp_register() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::AP,
            res: Res::ADD,
            pc_update: PcUpdate::REGULAR,
            ap_update: ApUpdate::REGULAR,
            fp_update: FpUpdate::REGULAR,
            opcode: Opcode::NOP,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let MaybeRelocatable::Int(num) = run_context.compute_dst_addr(&instruction) {
            assert_eq!(num, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }
}

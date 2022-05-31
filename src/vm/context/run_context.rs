use crate::types::instruction::{Instruction, Op1Addr, Register};
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::vm_memory::memory::Memory;
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
    #[allow(dead_code)]
    ///Returns the encoded instruction (the value at pc) and the immediate value (the value at pc + 1, if it exists in the memory).
    pub fn get_instruction_encoding(
        &self,
    ) -> Result<(&BigInt, Option<&MaybeRelocatable>), VirtualMachineError> {
        let encoding_ref: &BigInt;
        {
            if let Some(&MaybeRelocatable::Int(ref encoding)) = self.memory.get(&self.pc) {
                encoding_ref = encoding;
            } else {
                return Err(VirtualMachineError::InvalidInstructionEncoding);
            }
            let imm_addr = self
                .pc
                .add_num_addr(BigInt::from_i32(1).unwrap(), Some(self.prime.clone()));
            let optional_imm = self.memory.get(&imm_addr);
            Ok((encoding_ref, optional_imm))
        }
    }

    pub fn compute_dst_addr(&self, instruction: &Instruction) -> MaybeRelocatable {
        let base_addr = match instruction.dst_register {
            Register::AP => &self.ap,
            Register::FP => &self.fp,
        };
        base_addr.add_num_addr(instruction.off0.clone(), Some(self.prime.clone()))
    }

    pub fn compute_op0_addr(&self, instruction: &Instruction) -> MaybeRelocatable {
        let base_addr = match instruction.op0_register {
            Register::AP => &self.ap,
            Register::FP => &self.fp,
        };
        base_addr.add_num_addr(instruction.off1.clone(), Some(self.prime.clone()))
    }

    pub fn compute_op1_addr(
        &self,
        instruction: &Instruction,
        op0: Option<&MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.op1_addr {
            Op1Addr::FP => &self.fp,
            Op1Addr::AP => &self.ap,
            Op1Addr::Imm => match instruction.off2 == BigInt::from_i32(1).unwrap() {
                true => &self.pc,
                false => return Err(VirtualMachineError::ImmShouldBe1),
            },
            Op1Addr::Op0 => match op0 {
                Some(addr) => {
                    return Ok(addr.clone() + instruction.off2.clone() % self.prime.clone())
                }
                None => return Err(VirtualMachineError::UnknownOp0),
            },
        };
        Ok(base_addr.add_num_addr(instruction.off2.clone(), Some(self.prime.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::instruction::{ApUpdate, FpUpdate, Opcode, PcUpdate, Res};
    use crate::vm::vm_core::VirtualMachineError;

    #[test]
    fn get_instruction_encoding_successful_without_imm() {
        let mut run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };

        run_context.memory.insert(
            &MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
        );
        if let Ok((num_ref, None)) = run_context.get_instruction_encoding() {
            assert_eq!(num_ref.clone(), BigInt::from_i32(5).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn get_instruction_encoding_successful_with_imm() {
        let mut run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };

        run_context.memory.insert(
            &MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
        );
        run_context.memory.insert(
            &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            &MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
        );
        if let Ok((num_ref, Some(&MaybeRelocatable::Int(ref imm_addr_num_ref)))) =
            run_context.get_instruction_encoding()
        {
            assert_eq!(num_ref.clone(), BigInt::from_i32(5).unwrap());
            assert_eq!(imm_addr_num_ref.clone(), BigInt::from_i32(6).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn get_instruction_encoding_unsuccesful() {
        let mut run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };

        run_context.memory.insert(
            &MaybeRelocatable::Int(BigInt::from_i32(7).unwrap()),
            &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
        );
        if let Err(error) = run_context.get_instruction_encoding() {
            assert_eq!(error, VirtualMachineError::InvalidInstructionEncoding);
        } else {
            assert!(false);
        }
    }

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
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
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
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
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

    #[test]
    fn compute_op0_addr_for_ap_register() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::AP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::AP,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let MaybeRelocatable::Int(num) = run_context.compute_op0_addr(&instruction) {
            assert_eq!(num, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op0_addr_for_fp_register() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::FP,
            op1_addr: Op1Addr::AP,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let MaybeRelocatable::Int(num) = run_context.compute_op0_addr(&instruction) {
            assert_eq!(num, BigInt::from_i32(8).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op1_addr_for_fp_op1_addr() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::FP,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let Ok(MaybeRelocatable::Int(num)) = run_context.compute_op1_addr(&instruction, None) {
            assert_eq!(num, BigInt::from_i32(9).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op1_addr_for_ap_op1_addr() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::AP,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let Ok(MaybeRelocatable::Int(num)) = run_context.compute_op1_addr(&instruction, None) {
            assert_eq!(num, BigInt::from_i32(8).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op1_addr_for_imm_op1_addr_correct_off2() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(1).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::Imm,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let Ok(MaybeRelocatable::Int(num)) = run_context.compute_op1_addr(&instruction, None) {
            assert_eq!(num, BigInt::from_i32(5).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op1_addr_for_imm_op1_addr_incorrect_off2() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::Imm,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let Err(error) = run_context.compute_op1_addr(&instruction, None) {
            assert_eq!(error, VirtualMachineError::ImmShouldBe1);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op1_addr_for_op0_op1_addr_with_op0() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(1).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::Op0,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };

        let op0 = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        if let Ok(MaybeRelocatable::Int(num)) =
            run_context.compute_op1_addr(&instruction, Some(&op0))
        {
            assert_eq!(num, BigInt::from_i32(8).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn compute_op1_addr_for_op0_op1_addr_without_op0() {
        let instruction = Instruction {
            off0: BigInt::from_i32(1).unwrap(),
            off1: BigInt::from_i32(2).unwrap(),
            off2: BigInt::from_i32(3).unwrap(),
            imm: None,
            dst_register: Register::FP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::Op0,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::NOp,
        };

        let run_context = RunContext {
            memory: Memory::new(),
            pc: MaybeRelocatable::Int(BigInt::from_i32(4).unwrap()),
            ap: MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            fp: MaybeRelocatable::Int(BigInt::from_i32(6).unwrap()),
            prime: BigInt::from_i32(39).unwrap(),
        };
        if let Err(error) = run_context.compute_op1_addr(&instruction, None) {
            assert_eq!(error, VirtualMachineError::UnknownOp0);
        } else {
            assert!(false);
        }
    }
}

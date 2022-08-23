use crate::bigint;
use crate::types::instruction::{Instruction, Op1Addr, Register};
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use num_bigint::BigInt;

pub struct RunContext {
    pub pc: usize,
    pub ap: usize,
    pub fp: usize,
    pub prime: BigInt,
}

impl RunContext {
    pub fn get_pc(&self) -> MaybeRelocatable {
        MaybeRelocatable::from((0, self.pc))
    }
    pub fn get_ap(&self) -> MaybeRelocatable {
        MaybeRelocatable::from((1, self.ap))
    }
    pub fn get_fp(&self) -> MaybeRelocatable {
        MaybeRelocatable::from((1, self.fp))
    }
    pub fn compute_dst_addr(
        &self,
        instruction: &Instruction,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.dst_register {
            Register::AP => &self.get_ap(),
            Register::FP => &self.get_fp(),
        };
        base_addr.add_int_mod(&instruction.off0, &self.prime)
    }

    pub fn compute_op0_addr(
        &self,
        instruction: &Instruction,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.op0_register {
            Register::AP => &self.get_ap(),
            Register::FP => &self.get_fp(),
        };
        base_addr.add_int_mod(&instruction.off1, &self.prime)
    }

    pub fn compute_op1_addr(
        &self,
        instruction: &Instruction,
        op0: Option<&MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        let base_addr = match instruction.op1_addr {
            Op1Addr::FP => &self.get_fp(),
            Op1Addr::AP => &self.get_ap(),
            Op1Addr::Imm => match instruction.off2 == bigint!(1) {
                true => &self.get_pc(),
                false => return Err(VirtualMachineError::ImmShouldBe1),
            },
            Op1Addr::Op0 => match op0 {
                Some(addr) => return addr.add_int_mod(&instruction.off2, &self.prime),
                None => return Err(VirtualMachineError::UnknownOp0),
            },
        };
        base_addr.add_int_mod(&instruction.off2, &self.prime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint;
    use crate::types::instruction::{ApUpdate, FpUpdate, Opcode, PcUpdate, Res};

    #[test]
    fn compute_dst_addr_for_ap_register() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(6))),
            run_context.compute_dst_addr(&instruction)
        );
    }

    #[test]
    fn compute_dst_addr_for_fp_register() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(7))),
            run_context.compute_dst_addr(&instruction)
        );
    }

    #[test]
    fn compute_op0_addr_for_ap_register() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(7))),
            run_context.compute_op0_addr(&instruction)
        );
    }

    #[test]
    fn compute_op0_addr_for_fp_register() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(8))),
            run_context.compute_op0_addr(&instruction)
        );
    }

    #[test]
    fn compute_op1_addr_for_fp_op1_addr() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(9))),
            run_context.compute_op1_addr(&instruction, None)
        );
    }

    #[test]
    fn compute_op1_addr_for_ap_op1_addr() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(8))),
            run_context.compute_op1_addr(&instruction, None)
        );
    }

    #[test]
    fn compute_op1_addr_for_imm_op1_addr_correct_off2() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(1),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(5))),
            run_context.compute_op1_addr(&instruction, None)
        );
    }

    #[test]
    fn compute_op1_addr_for_imm_op1_addr_incorrect_off2() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };

        let error = run_context.compute_op1_addr(&instruction, None);
        assert_eq!(error, Err(VirtualMachineError::ImmShouldBe1));
        assert_eq!(
            error.unwrap_err().to_string(),
            "In immediate mode, off2 should be 1"
        );
    }

    #[test]
    fn compute_op1_addr_for_op0_op1_addr_with_op0() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(1),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };

        let op0 = MaybeRelocatable::from(bigint!(7));
        assert_eq!(
            Ok(MaybeRelocatable::Int(bigint!(8))),
            run_context.compute_op1_addr(&instruction, Some(&op0))
        );
    }

    #[test]
    fn compute_op1_addr_for_op0_op1_addr_without_op0() {
        let instruction = Instruction {
            off0: bigint!(1),
            off1: bigint!(2),
            off2: bigint!(3),
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
            pc: MaybeRelocatable::from(bigint!(4)),
            ap: MaybeRelocatable::from(bigint!(5)),
            fp: MaybeRelocatable::from(bigint!(6)),
            prime: bigint!(39),
        };

        let error = run_context.compute_op1_addr(&instruction, None);
        assert_eq!(error, Err(VirtualMachineError::UnknownOp0));
        assert_eq!(
            error.unwrap_err().to_string(),
            "op0 must be known in double dereference"
        );
    }
}

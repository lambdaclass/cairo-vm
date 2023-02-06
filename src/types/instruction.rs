use felt::Felt;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
};

use crate::vm::decoding::decoder::decode_instruction;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Register {
    AP,
    FP,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Instruction {
    pub off0: isize,
    pub off1: isize,
    pub off2: isize,
    pub imm: Option<Felt>,
    pub dst_register: Register,
    pub op0_register: Register,
    pub op1_addr: Op1Addr,
    pub res: Res,
    pub pc_update: PcUpdate,
    pub ap_update: ApUpdate,
    pub fp_update: FpUpdate,
    pub opcode: Opcode,
}

impl Display for Instruction {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "off0: {}", self.off0)?;
        writeln!(f, "off1: {}", self.off1)?;
        writeln!(f, "off2: {}", self.off2)?;
        writeln!(f, "imm: {:?}", self.imm)?;
        writeln!(f, "dst_register: {:?}", self.dst_register)?;
        writeln!(f, "op0_register: {:?}", self.op0_register)?;
        writeln!(f, "op1_addr: {:?}", self.op1_addr)?;
        writeln!(f, "res: {:?}", self.res)?;
        writeln!(f, "pc_update: {:?}", self.pc_update)?;
        writeln!(f, "ap_update: {:?}", self.ap_update)?;
        writeln!(f, "fp_update: {:?}", self.fp_update)?;
        writeln!(f, "opcode: {:?}", self.opcode)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Op1Addr {
    Imm,
    AP,
    FP,
    Op0,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Res {
    Op1,
    Add,
    Mul,
    Unconstrained,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PcUpdate {
    Regular,
    Jump,
    JumpRel,
    Jnz,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApUpdate {
    Regular,
    Add,
    Add1,
    Add2,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FpUpdate {
    Regular,
    APPlus2,
    Dst,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Opcode {
    NOp,
    AssertEq,
    Call,
    Ret,
}

impl Instruction {
    pub fn size(&self) -> usize {
        match self.imm {
            Some(_) => 2,
            None => 1,
        }
    }
}

// Returns True if the given instruction looks like a call instruction.
pub(crate) fn is_call_instruction(encoded_instruction: &Felt, imm: Option<&Felt>) -> bool {
    let encoded_i64_instruction: i64 = match encoded_instruction.to_i64() {
        Some(num) => num,
        None => return false,
    };
    let instruction = match decode_instruction(encoded_i64_instruction, imm) {
        Ok(inst) => inst,
        Err(_) => return false,
    };
    instruction.res == Res::Op1
        && (instruction.pc_update == PcUpdate::Jump || instruction.pc_update == PcUpdate::JumpRel)
        && instruction.ap_update == ApUpdate::Add2
        && instruction.fp_update == FpUpdate::APPlus2
        && instruction.opcode == Opcode::Call
}

#[cfg(test)]
mod tests {
    
    use super::*;
    use num_bigint::BigUint;
    use felt::bigint_felt::FeltBigInt;

    #[test]
    fn is_call_instruction_true() {
        let encoded_instruction = Felt::new(1226245742482522112_i64);
        assert!(is_call_instruction(
            &encoded_instruction,
            Some(&Felt::new(2))
        ));
    }
    #[test]
    fn is_call_instruction_false() {
        let encoded_instruction = Felt::new(4612671187288031229_i64);
        assert!(!is_call_instruction(&encoded_instruction, None));
    }

    #[test]
    fn instruction_size() {
        let encoded_instruction = Felt::new(1226245742482522112_i64);
        let instruction =
            decode_instruction(encoded_instruction.to_i64().unwrap(), Some(&Felt::new(2))).unwrap();
        assert_eq!(instruction.size(), 2);
    }

    #[test]
    fn test_instruction_display() {
        let test_instruction = Instruction {
            off0: 1,
            off1: 2,
            off2: 3,
            imm: Some(Felt {
                value: FeltBigInt {
                    val: BigUint {
                        data: vec![0],
                    },
                },
            }),
            dst_register: Register::AP,
            op0_register: Register::AP,
            op1_addr: Op1Addr::Imm,
            res: Res::Add,
            pc_update: PcUpdate::Regular,
            ap_update: ApUpdate::Regular,
            fp_update: FpUpdate::Regular,
            opcode: Opcode::Call,
        };

        let expected_output = "off0: 1\noff1: 2\noff2: 3\nimm: Some(Felt { value: FeltBigInt { val: BigUint { data: [0] } } })\ndst_register: AP\nop0_register: AP\nop1_addr: Imm\nres: Add\npc_update: Regular\nap_update: Regular\nfp_update: Regular\nopcode: Call\n";
        assert_eq!(expected_output, format!("{}", test_instruction));
    }
}

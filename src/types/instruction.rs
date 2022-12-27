use num_bigint::BigInt;
use num_traits::ToPrimitive;
use serde::Deserialize;

use crate::vm::decoding::decoder::decode_instruction;

#[derive(Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Register {
    AP,
    FP,
}

#[derive(Debug, PartialEq)]
pub struct Instruction {
    pub off0: isize,
    pub off1: isize,
    pub off2: isize,
    pub imm: Option<BigInt>,
    pub dst_register: Register,
    pub op0_register: Register,
    pub op1_addr: Op1Addr,
    pub res: Res,
    pub pc_update: PcUpdate,
    pub ap_update: ApUpdate,
    pub fp_update: FpUpdate,
    pub opcode: Opcode,
}

#[derive(Debug, PartialEq)]
pub enum Op1Addr {
    Imm,
    AP,
    FP,
    Op0,
}

#[derive(Debug, PartialEq)]
pub enum Res {
    Op1,
    Add,
    Mul,
    Unconstrained,
}

#[derive(Debug, PartialEq)]
pub enum PcUpdate {
    Regular,
    Jump,
    JumpRel,
    Jnz,
}

#[derive(Debug, PartialEq)]
pub enum ApUpdate {
    Regular,
    Add,
    Add1,
    Add2,
}

#[derive(Debug, PartialEq)]
pub enum FpUpdate {
    Regular,
    APPlus2,
    Dst,
}

#[derive(Debug, PartialEq)]
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
pub(crate) fn is_call_instruction(encoded_instruction: &BigInt, imm: Option<&BigInt>) -> bool {
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
    use crate::bigint;

    use super::*;

    #[test]
    fn is_call_instruction_true() {
        let encoded_instruction = bigint!(1226245742482522112_i64);
        assert!(is_call_instruction(&encoded_instruction, Some(&bigint!(2))));
    }
    #[test]
    fn is_call_instruction_false() {
        let encoded_instruction = bigint!(4612671187288031229_i64);
        assert!(!is_call_instruction(&encoded_instruction, None));
    }
}

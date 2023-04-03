use felt::Felt252;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

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
    pub dst_register: Register,
    pub op0_register: Register,
    pub op1_addr: Op1Addr,
    pub res: Res,
    pub pc_update: PcUpdate,
    pub ap_update: ApUpdate,
    pub fp_update: FpUpdate,
    pub opcode: Opcode,
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
        match self.op1_addr {
            Op1Addr::Imm => 2,
            _ => 1,
        }
    }
}

// Returns True if the given instruction looks like a call instruction.
pub(crate) fn is_call_instruction(encoded_instruction: &Felt252) -> bool {
    // Flags start on the 48th bit.
    const FLAGS_OFFSET: u64 = 48;

    const RES_LOGIC_OFF: u64 = 5 + FLAGS_OFFSET;
    const PC_UPDATE_OFF: u64 = 7 + FLAGS_OFFSET;
    const AP_UPDATE_OFF: u64 = 10 + FLAGS_OFFSET;
    const OPCODE_OFF: u64 = 12 + FLAGS_OFFSET;

    const OP1_SRC_OFF: u64 = FLAGS_OFFSET;
    const OP1_SRC_MASK: u64 = 0x001C << OP1_SRC_OFF;

    const INSTR_MASK: u64 = 0xffff_0000_0000_0000;

    const RES_OP1: u64 = 0u64 << RES_LOGIC_OFF;
    const PC_UPDATE_JMP: u64 = 1u64 << PC_UPDATE_OFF;
    const PC_UPDATE_JMPREL: u64 = 2u64 << PC_UPDATE_OFF;
    const AP_UPDATE_ADD2: u64 = 0u64 << AP_UPDATE_OFF;
    //Not a typo, the same bit determines both.
    const FP_UPDATE_APPLUS2: u64 = 1u64 << OPCODE_OFF;
    const OPCODE_CALL: u64 = 1u64 << OPCODE_OFF;

    const CALL: u64 = RES_OP1 | AP_UPDATE_ADD2 | FP_UPDATE_APPLUS2 | OPCODE_CALL | PC_UPDATE_JMP;
    const CALL_REL: u64 =
        RES_OP1 | AP_UPDATE_ADD2 | FP_UPDATE_APPLUS2 | OPCODE_CALL | PC_UPDATE_JMPREL;

    let Some(instr) = encoded_instruction.to_u64() else {
        return false;
    };

    /*
        0 => Op1Addr::Op0,
        1 => Op1Addr::Imm,
        2 => Op1Addr::FP,
        4 => Op1Addr::AP,
        _ => Invalid
    */
    let op1_src = (instr & OP1_SRC_MASK) >> OP1_SRC_OFF;
    let instr = instr & INSTR_MASK & !OP1_SRC_MASK;
    dbg!(op1_src, OP1_SRC_MASK, instr, CALL, CALL_REL);
    [0, 1, 2, 4].contains(&op1_src) &&
    /*
     * instruction.res == Res::Op1
     *  && (instruction.pc_update == PcUpdate::Jump || instruction.pc_update == PcUpdate::JumpRel)
     *  && instruction.ap_update == ApUpdate::Add2
     *  && instruction.fp_update == FpUpdate::APPlus2
     *  && instruction.opcode == Opcode::Call
     */
    [CALL, CALL_REL].contains(&instr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::decoding::decoder::decode_instruction;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn is_call_instruction_true() {
        let encoded_instruction = Felt252::new(1226245742482522112_i64);
        assert!(is_call_instruction(&encoded_instruction));
    }
    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn is_call_instruction_false() {
        let encoded_instruction = Felt252::new(4612671187288031229_i64);
        assert!(!is_call_instruction(&encoded_instruction));
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn instruction_size() {
        let encoded_instruction = Felt252::new(1226245742482522112_i64);
        let instruction = decode_instruction(encoded_instruction.to_u64().unwrap()).unwrap();
        assert_eq!(instruction.size(), 2);
    }
}

use crate::vm::instruction;
use num_bigint::BigUint;

//  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
// 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0

const DST_REG_MASK: i32 = 0x0001;
const DST_REG_OFF: i32 = 0;
const OP0_REG_MASK: i32 = 0x0002;
const OP0_REG_OFF: i32 = 1;
const OP1_SRC_MASK: i32 = 0x001C;
const OP1_SRC_OFF: i32 = 2;
const RES_LOGIC_MASK: i32 = 0x0060;
const RES_LOGIC_OFF: i32 = 5;
const PC_UPDATE_MASK: i32 = 0x0380;
const PC_UPDATE_OFF: i32 = 7;
const AP_UPDATE_MASK: i32 = 0x0C00;
const AP_UPDATE_OFF: i32 = 10;
const OPCODE_MASK: i32 = 0x7000;
const OPCODE_OFF: i32 = 12;

// Flags start on the 48th bit.
const FLAGS_OFFSET: i32 = 48;
const OFF0_OFF: i32 = 0;
const OFF1_OFF: i32 = 16;
const OFF2_OFF: i32 = 32;
const OFFX_MASK: i32 = 0xFFFF;
/*
/// Decodes an instruction. The encoding is little endian, so flags go from bit 63 to 48.
pub fn decode_instruction(encoded_instr:i32, imm:Option<BigUint>) -> instruction::Instruction {
    let off0 = encoded_instr >> OFF0_OFF & OFFX_MASK;
    let off1 = encoded_instr >> OFF1_OFF & OFFX_MASK;
    let off2 = encoded_instr >> OFF2_OFF & OFFX_MASK;
    let flags = encoded_instr >> FLAGS_OFFSET;
    let dst_reg_num = (flags & DST_REG_MASK) >> DST_REG_OFF;
    let op0_reg_num = (flags & OP0_REG_MASK) >> OP0_REG_OFF;
    let op1_reg_num = (flags & OP1_REG_MASK) >> OP1_REG_OFF;
    let res_logic_num = (flags & RES_LOGIC_MASK) >> RES_LOGIC_OFF;
    let pc_update_num = (flags & PC_UPDATE_MASK) >> PC_UPDATE_OFF;
    let ap_update_num = (flags & AP_UPDATE_MASK) >> AP_UPDATE_OFF;
    let opcode_num = (flags & OPCODE_MASK) >> OPCODE_OFF;

    let dst_reg = match dst_reg_num {
        0 => instruction::Register::AP,
        1 => instruction::Register::FP,
        _ => {},
    };

    let op0_reg = match op0_reg_num {
        0 => instruction::Register::AP,
        1 => instruction::Register::FP,
        _ => {},
    };

    let op1_addr = match op1_reg_num {
        0 => instruction::Op1Addr::OP0,
        1 => instruction::Op1Addr::IMM,
        2 => instruction::Op1Addr::AP,
        4 => instruction::Op1Addr::FP,
        _ => {},
    };

    let pc_update = match pc_update_num {
        0 => instruction::PcUpdate::REGULAR,
        1 => instruction::PcUpdate::JUMP,
        2 => instruction::PcUpdate::JUMP_REL,
        4 => instruction::PcUpdate::JNZ,
        _ => {},
    };

    let res = match res_logic_num {
        0 if pc_update == instruction::PcUpdate::JNZ => instruction::Res::UNCONSTRAINED,
        0 => instruction::Res::OP1
        1 => instruction::Res::ADD,
        2 => instruction::Res::MUL,
        _ => {},
    };

    let opcode = match opcode_num {
        0 => instruction::Opcode::NOP,
        1 => instruction::Opcode::ASSERT_EQ,
        2 => instruction::Opcode::RET,
        4 => instruction::Opcode::CALL,
        _ => {},
    };

    let ap_update = match ap_update_num {
        0 if opcode == instruction::Opcode::CALL => instruction::ApUpdate::ADD2,
        0 => instruction::ApUpdate::REGULAR,
        1 => instruction::ApUpdate::ADD,
        2 => instruction::ApUpdate::ADD1,
        _ => {},
    };

    let fp_update = match opcode {
        instruction::Opcode::CALL => instruction::FpUpdate::AP_PLUS2,
        instruction::Opcode::RET => instruction::FpUpdate::DST,
        _ => instruction::FpUpdate::REGULAR,
    };

    let instruction = instruction::Instruction {
        off0,
        off1,
        off2,
        imm,
        dst_reg,
        op0_reg,
        op1_addr,
        res,
        pc_update,
        ap_update,
        fp_update,
        opcode
    }
}
*/

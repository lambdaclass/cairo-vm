use crate::vm::instruction;
use num_bigint::BigInt;
use num_traits::FromPrimitive;

//  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
// 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0

const DST_REG_MASK: i64 = 0x0001;
const DST_REG_OFF: i64 = 0;
const OP0_REG_MASK: i64 = 0x0002;
const OP0_REG_OFF: i64 = 1;
const OP1_SRC_MASK: i64 = 0x001C;
const OP1_SRC_OFF: i64 = 2;
const RES_LOGIC_MASK: i64 = 0x0060;
const RES_LOGIC_OFF: i64 = 5;
const PC_UPDATE_MASK: i64 = 0x0380;
const PC_UPDATE_OFF: i64 = 7;
const AP_UPDATE_MASK: i64 = 0x0C00;
const AP_UPDATE_OFF: i64 = 10;
const OPCODE_MASK: i64 = 0x7000;
const OPCODE_OFF: i64 = 12;

// Flags start on the 48th bit.
const FLAGS_OFFSET: i64 = 48;
const OFF0_OFF: i64 = 0;
const OFF1_OFF: i64 = 16;
const OFF2_OFF: i64 = 32;
const OFFX_MASK: i64 = 0xFFFF;

/// Decodes an instruction. The encoding is little endian, so flags go from bit 63 to 48.
pub fn decode_instruction(encoded_instr: i64, imm: Option<BigInt>) -> instruction::Instruction {
    // Grab offsets and convert them from little endian format.
    let off0 = decode_offset(encoded_instr >> OFF0_OFF & OFFX_MASK);
    let off1 = decode_offset(encoded_instr >> OFF1_OFF & OFFX_MASK);
    let off2 = decode_offset(encoded_instr >> OFF2_OFF & OFFX_MASK);
    // Grab flags
    let flags = encoded_instr >> FLAGS_OFFSET;
    // Grab individual flags
    let dst_reg_num = (flags & DST_REG_MASK) >> DST_REG_OFF;
    let op0_reg_num = (flags & OP0_REG_MASK) >> OP0_REG_OFF;
    let op1_src_num = (flags & OP1_SRC_MASK) >> OP1_SRC_OFF;
    let res_logic_num = (flags & RES_LOGIC_MASK) >> RES_LOGIC_OFF;
    let pc_update_num = (flags & PC_UPDATE_MASK) >> PC_UPDATE_OFF;
    let ap_update_num = (flags & AP_UPDATE_MASK) >> AP_UPDATE_OFF;
    let opcode_num = (flags & OPCODE_MASK) >> OPCODE_OFF;

    // Match each flag to its corresponding enum value
    let dst_register = match dst_reg_num {
        0 => instruction::Register::AP,
        1 => instruction::Register::FP,
        _ => panic!("Invalid instruction"),
    };

    let op0_register = match op0_reg_num {
        0 => instruction::Register::AP,
        1 => instruction::Register::FP,
        _ => panic!("Invalid instruction"),
    };

    let op1_addr = match op1_src_num {
        0 => instruction::Op1Addr::OP0,
        1 => instruction::Op1Addr::IMM,
        2 => instruction::Op1Addr::AP,
        4 => instruction::Op1Addr::FP,
        _ => panic!("Invalid instruction"),
    };

    let pc_update = match pc_update_num {
        0 => instruction::PcUpdate::REGULAR,
        1 => instruction::PcUpdate::JUMP,
        2 => instruction::PcUpdate::JUMP_REL,
        4 => instruction::PcUpdate::JNZ,
        _ => panic!("Invalid instruction"),
    };

    let res = match res_logic_num {
        0 if matches!(pc_update, instruction::PcUpdate::JNZ) => instruction::Res::UNCONSTRAINED,
        0 => instruction::Res::OP1,
        1 => instruction::Res::ADD,
        2 => instruction::Res::MUL,
        _ => panic!("Invalid instruction"),
    };

    let opcode = match opcode_num {
        0 => instruction::Opcode::NOP,
        1 => instruction::Opcode::CALL,
        2 => instruction::Opcode::RET,
        4 => instruction::Opcode::ASSERT_EQ,
        _ => panic!("Invalid instruction"),
    };

    let ap_update = match ap_update_num {
        0 if matches!(opcode, instruction::Opcode::CALL) => instruction::ApUpdate::ADD2,
        0 => instruction::ApUpdate::REGULAR,
        1 => instruction::ApUpdate::ADD,
        2 => instruction::ApUpdate::ADD1,
        _ => panic!("Invalid instruction"),
    };

    let fp_update = match opcode {
        instruction::Opcode::CALL => instruction::FpUpdate::AP_PLUS2,
        instruction::Opcode::RET => instruction::FpUpdate::DST,
        _ => instruction::FpUpdate::REGULAR,
    };

    instruction::Instruction {
        // TODO: Replace or confirm the unrwap is safe
        off0: BigInt::from_i64(off0).unwrap(),
        off1: BigInt::from_i64(off1).unwrap(),
        off2: BigInt::from_i64(off2).unwrap(),
        imm,
        dst_register,
        op0_register,
        op1_addr,
        res,
        pc_update,
        ap_update,
        fp_update,
        opcode,
    }
}

fn decode_offset(offset:i64) -> i64 {
    let vectorized_offset:[u8;8] = offset.to_le_bytes();
    let offset_16b_encoded = u16::from_le_bytes([vectorized_offset[0], vectorized_offset[1]]);
    let complement_const = 0x8000u16;
    let (offset_16b, _) = offset_16b_encoded.overflowing_sub(complement_const);
    i64::from(offset_16b as i16)
}

#[cfg(test)]
mod decoder_test {
    use super::*;

    #[test]
    fn decode_flags_call_add_jmp_add_imm_fp_fp() {
        //  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
        // 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0
        //   |    CALL|      ADD|     JUMP|      ADD|    IMM|     FP|     FP
        //  0  0  0  1      0  1   0  0  1      0  1 0  0  1       1       1
        //  0001 0100 1010 0111 = 0x14A7; offx = 0
        let inst = decode_instruction(0x14A7800080008000, None);
        assert_eq!(matches!(inst.dst_register, instruction::Register::FP), true);
        assert_eq!(matches!(inst.op0_register, instruction::Register::FP), true);
        assert_eq!(matches!(inst.op1_addr, instruction::Op1Addr::IMM), true);
        assert_eq!(matches!(inst.res, instruction::Res::ADD), true);
        assert_eq!(matches!(inst.pc_update, instruction::PcUpdate::JUMP), true);
        assert_eq!(matches!(inst.ap_update, instruction::ApUpdate::ADD), true);
        assert_eq!(matches!(inst.opcode, instruction::Opcode::CALL), true);
        assert_eq!(
            matches!(inst.fp_update, instruction::FpUpdate::AP_PLUS2),
            true
        );
    }

    #[test]
    fn decode_flags_ret_add1_jmp_rel_mul_ap_ap_ap() {
        //  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
        // 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0
        //   |     RET|     ADD1| JUMP_REL|      MUL|     AP|     AP|     AP
        //  0  0  1  0      1  0   0  1  0      1  0 0  1  0       0       0
        //  0010 1001 0100 1000 = 0x2948; offx = 0
        let inst = decode_instruction(0x2948800080008000, None);
        assert_eq!(matches!(inst.dst_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op0_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op1_addr, instruction::Op1Addr::AP), true);
        assert_eq!(matches!(inst.res, instruction::Res::MUL), true);
        assert_eq!(
            matches!(inst.pc_update, instruction::PcUpdate::JUMP_REL),
            true
        );
        assert_eq!(matches!(inst.ap_update, instruction::ApUpdate::ADD1), true);
        assert_eq!(matches!(inst.opcode, instruction::Opcode::RET), true);
        assert_eq!(matches!(inst.fp_update, instruction::FpUpdate::DST), true);
    }

    #[test]
    fn decode_flags_assrt_add_jnz_mul_fp_ap_ap() {
        //  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
        // 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0
        //   |ASSRT_EQ|      ADD|      JNZ|      MUL|     FP|     AP|     AP
        //  0  1  0  0      1  0   1  0  0      1  0 1  0  0       0       0
        //  0100 1010 0101 0000 = 0x4A50; offx = 0
        let inst = decode_instruction(0x4A50800080008000, None);
        assert_eq!(matches!(inst.dst_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op0_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op1_addr, instruction::Op1Addr::FP), true);
        assert_eq!(matches!(inst.res, instruction::Res::MUL), true);
        assert_eq!(matches!(inst.pc_update, instruction::PcUpdate::JNZ), true);
        assert_eq!(matches!(inst.ap_update, instruction::ApUpdate::ADD1), true);
        assert_eq!(matches!(inst.opcode, instruction::Opcode::ASSERT_EQ), true);
        assert_eq!(
            matches!(inst.fp_update, instruction::FpUpdate::REGULAR),
            true
        );
    }

    #[test]
    fn decode_flags_assrt_add2_jnz_uncon_op0_ap_ap() {
        //  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
        // 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0
        //   |ASSRT_EQ|     ADD2|      JNZ|UNCONSTRD|    OP0|     AP|     AP
        //  0  1  0  0      0  0   1  0  0      0  0 0  0  0       0       0
        //  0100 0010 0000 0000 = 0x4200; offx = 0
        let inst = decode_instruction(0x4200800080008000, None);
        assert_eq!(matches!(inst.dst_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op0_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op1_addr, instruction::Op1Addr::OP0), true);
        assert_eq!(matches!(inst.res, instruction::Res::UNCONSTRAINED), true);
        assert_eq!(matches!(inst.pc_update, instruction::PcUpdate::JNZ), true);
        assert_eq!(
            matches!(inst.ap_update, instruction::ApUpdate::REGULAR),
            true
        );
        assert_eq!(matches!(inst.opcode, instruction::Opcode::ASSERT_EQ), true);
        assert_eq!(
            matches!(inst.fp_update, instruction::FpUpdate::REGULAR),
            true
        );
    }

    #[test]
    fn decode_flags_nop_regu_regu_op1_op0_ap_ap() {
        //  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
        // 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0
        //   |     NOP|  REGULAR|  REGULAR|      OP1|    OP0|     AP|     AP
        //  0  0  0  0      0  0   0  0  0      0  0 0  0  0       0       0
        //  0000 0000 0000 0000 = 0x0000; offx = 0
        let inst = decode_instruction(0x0000800080008000, None);
        assert_eq!(matches!(inst.dst_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op0_register, instruction::Register::AP), true);
        assert_eq!(matches!(inst.op1_addr, instruction::Op1Addr::OP0), true);
        assert_eq!(matches!(inst.res, instruction::Res::OP1), true);
        assert_eq!(
            matches!(inst.pc_update, instruction::PcUpdate::REGULAR),
            true
        );
        assert_eq!(
            matches!(inst.ap_update, instruction::ApUpdate::REGULAR),
            true
        );
        assert_eq!(matches!(inst.opcode, instruction::Opcode::NOP), true);
        assert_eq!(
            matches!(inst.fp_update, instruction::FpUpdate::REGULAR),
            true
        );
    }

    #[test]
    fn decode_offset_negative() {
        //  0|  opcode|ap_update|pc_update|res_logic|op1_src|op0_reg|dst_reg
        // 15|14 13 12|    11 10|  9  8  7|     6  5|4  3  2|      1|      0
        //   |     NOP|  REGULAR|  REGULAR|      OP1|    OP0|     AP|     AP
        //  0  0  0  0      0  0   0  0  0      0  0 0  0  0       0       0
        //  0000 0000 0000 0000 = 0x0000; offx = 0
        let inst = decode_instruction(0x0000800180007FFF, None);
        assert_eq!(inst.off0, BigInt::from_i32(-1).unwrap());
        assert_eq!(inst.off1, BigInt::from_i32(0).unwrap());
        assert_eq!(inst.off2, BigInt::from_i32(1).unwrap());
    }
}

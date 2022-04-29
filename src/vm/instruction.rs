pub struct Instruction {
    off0: i16,
    off1: i16,
    off2: i16,
    imm: Option<i64>,
    dst_register: Register,
    op0_register: Register,
    op1_addr: Op1Addr,
    res: Res,
    pc_update: PcUpdate,
    ap_update: ApUpdate
    fp_update: FpUpdate,
    opcode: Opcode

}

pub enum Register {
    AP,
    FP
}

pub enum Op1Addr {
    IMM,
    AP,
    FP,
    OP0
}

pub enum Res {
    OP1,
    ADD,
    MUL,
    UNCONSTRAINED
}

pub enum PcUpdate {
    REGULAR,
    JUMP,
    JUMP_REL,
    JNZ
}

pub enum ApUpdate {
    REGULAR,
    ADD,
    ADD1,
    ADD2
}

pub enum FpUpdate {
    REGULAR,
    AP_PLUS2,
    DST
}

pub enum Opcode {
    NOP,
    ASSERT_EQ,
    CALL,
    RET
}

trait Size { 
    fn size(&self) -> i32;
}
impl size for Instruction {
    fn size(&self) -> i32 {
        match self.imm {
            Some(imm) => 2
            None => 1
        }
    }
}

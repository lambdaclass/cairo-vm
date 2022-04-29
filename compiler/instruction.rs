use num_bigint::BigUint;

num Register {
    AP,
    FP
}

pub struct Instruction {
    off0: BigUint,
    off1: BigUint,
    off2: BigUint,
    imm: Option<BigUint>,
    dst_register: Register,
    op0_register: Register,
    op1_addr: Op1Addr,
    res: Res,
    pc_update: PcUpdate,
    ap_update: ApUpdate
    fp_update: FpUpdate,
    opcode: Opcode
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

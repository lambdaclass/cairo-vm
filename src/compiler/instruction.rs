use num_bigint::BigInt;

pub enum Register {
    AP,
    FP
}

pub struct Instruction {
    pub off0: BigInt,
    pub off1: BigInt,
    pub off2: BigInt,
    pub imm: Option<BigInt>,
    pub dst_register: Register,
    pub op0_register: Register,
    pub op1_addr: Op1Addr,
    pub res: Res,
    pub pc_update: PcUpdate,
    pub ap_update: ApUpdate,
    pub fp_update: FpUpdate,
    pub opcode: Opcode
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

impl Instruction {
    pub fn size(&self) -> i64 {
        match self.imm {
            Some(imm) => return 2,
            None => return 1,
        };
    }
}

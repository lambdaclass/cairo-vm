use num_bigint::BigInt;

#[derive(Debug, PartialEq)]
pub enum Register {
    AP,
    FP,
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
    JNZ,
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
    AsseertEq,
    Call,
    Ret,
}

impl Instruction {
    pub fn size(&self) -> i32 {
        match self.imm {
            Some(_) => 2,
            None => 1,
        }
    }
}

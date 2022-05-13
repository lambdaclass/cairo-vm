use num_bigint::BigInt;
use crate::vm::relocatable::MaybeRelocatable;

#[derive(Clone)]
pub struct Program {
    pub builtins: Vec<String>,
    pub prime: BigInt,
    pub data: Vec<MaybeRelocatable>,
}

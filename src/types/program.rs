use crate::types::relocatable::MaybeRelocatable;
use crate::vm::serializable_utils;
use num_bigint::BigInt;

#[derive(Clone)]
pub struct Program {
    pub builtins: Vec<String>,
    pub prime: BigInt,
    pub data: Vec<MaybeRelocatable>,
    pub main: Option<usize>,
}

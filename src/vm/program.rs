use num_bigint::BigInt;

#[derive(Clone)]
pub struct Program {
    pub builtins: Vec<String>,
    pub prime: BigInt,
}

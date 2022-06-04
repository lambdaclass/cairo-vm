use crate::serde::deserialize_program;
use crate::types::relocatable::MaybeRelocatable;
use num_bigint::BigInt;

#[derive(Clone)]
pub struct Program {
    pub builtins: Vec<String>,
    pub prime: BigInt,
    pub data: Vec<MaybeRelocatable>,
    pub main: Option<usize>,
}
#[allow(dead_code)]
impl Program {
    fn new(path: &str) -> Program {
        deserialize_program::deserialize_program(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;

    #[test]
    fn deserialize_program_test() {
        let program: Program = Program::new("tests/support/valid_program_a.json");

        let builtins: Vec<String> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i64(1000).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i64(5189976364521848832).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i64(2000).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i64(5201798304953696256).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i64(2345108766317314046).unwrap()),
        ];

        assert_eq!(
            program.prime,
            BigInt::parse_bytes(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481",
                10
            )
            .unwrap()
        );
        assert_eq!(program.builtins, builtins);
        assert_eq!(program.data, data);
        assert_eq!(program.main, Some(0));
    }
}

use crate::{
    serde::deserialize_program::{deserialize_program, HintParams, Identifier, ReferenceManager},
    types::{errors::program_errors::ProgramError, relocatable::MaybeRelocatable},
};
use felt::{Felt, PRIME_STR};
use std::{
    fs::File,
    io::{BufReader, Read},
    {collections::HashMap, path::Path},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub builtins: Vec<String>,
    pub prime: String,
    pub data: Vec<MaybeRelocatable>,
    pub constants: HashMap<String, Felt>,
    pub main: Option<usize>,
    //start and end labels will only be used in proof-mode
    pub start: Option<usize>,
    pub end: Option<usize>,
    pub hints: HashMap<usize, Vec<HintParams>>,
    pub reference_manager: ReferenceManager,
    pub identifiers: HashMap<String, Identifier>,
}

impl Program {
    pub fn from_file(path: &Path, entrypoint: Option<&str>) -> Result<Program, ProgramError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        deserialize_program(reader, entrypoint)
    }

    pub fn from_reader(
        reader: impl Read,
        entrypoint: Option<&str>,
    ) -> Result<Program, ProgramError> {
        deserialize_program(reader, entrypoint)
    }
}

impl Default for Program {
    fn default() -> Self {
        Program {
            builtins: Vec::new(),
            prime: PRIME_STR.to_string(),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            start: None,
            end: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt_str;
    use felt::NewFelt;
    use num_traits::Zero;

    #[test]
    fn deserialize_program_test() {
        let program: Program = Program::from_file(
            Path::new("cairo_programs/manually_compiled/valid_program_a.json"),
            Some("main"),
        )
        .expect("Failed to deserialize program");

        let builtins: Vec<String> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            MaybeRelocatable::Int(Felt::new(5189976364521848832_i64)),
            MaybeRelocatable::Int(Felt::new(1000)),
            MaybeRelocatable::Int(Felt::new(5189976364521848832_i64)),
            MaybeRelocatable::Int(Felt::new(2000)),
            MaybeRelocatable::Int(Felt::new(5201798304953696256_i64)),
            MaybeRelocatable::Int(Felt::new(2345108766317314046_i64)),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.Args"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Args".to_string()),
                members: Some(HashMap::new()),
            },
        );
        identifiers.insert(
            String::from("__main__.main.ImplicitArgs"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.ImplicitArgs".to_string()),
                members: Some(HashMap::new()),
            },
        );
        identifiers.insert(
            String::from("__main__.main.Return"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Return".to_string()),
                members: Some(HashMap::new()),
            },
        );
        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt::zero()),
                full_name: None,
                members: None,
            },
        );

        assert_eq!(program.prime, PRIME_STR.to_string());
        assert_eq!(program.builtins, builtins);
        assert_eq!(program.data, data);
        assert_eq!(program.main, Some(0));
        assert_eq!(program.identifiers, identifiers);
    }

    /// Deserialize a program without an entrypoint.
    #[test]
    fn deserialize_program_without_entrypoint_test() {
        let program: Program = Program::from_file(
            Path::new("cairo_programs/manually_compiled/valid_program_a.json"),
            None,
        )
        .expect("Failed to deserialize program");

        let builtins: Vec<String> = Vec::new();
        let data: Vec<MaybeRelocatable> = vec![
            MaybeRelocatable::Int(Felt::new(5189976364521848832_i64)),
            MaybeRelocatable::Int(Felt::new(1000)),
            MaybeRelocatable::Int(Felt::new(5189976364521848832_i64)),
            MaybeRelocatable::Int(Felt::new(2000)),
            MaybeRelocatable::Int(Felt::new(5201798304953696256_i64)),
            MaybeRelocatable::Int(Felt::new(2345108766317314046_i64)),
        ];

        let mut identifiers: HashMap<String, Identifier> = HashMap::new();

        identifiers.insert(
            String::from("__main__.main"),
            Identifier {
                pc: Some(0),
                type_: Some(String::from("function")),
                value: None,
                full_name: None,
                members: None,
            },
        );
        identifiers.insert(
            String::from("__main__.main.Args"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Args".to_string()),
                members: Some(HashMap::new()),
            },
        );
        identifiers.insert(
            String::from("__main__.main.ImplicitArgs"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.ImplicitArgs".to_string()),
                members: Some(HashMap::new()),
            },
        );
        identifiers.insert(
            String::from("__main__.main.Return"),
            Identifier {
                pc: None,
                type_: Some(String::from("struct")),
                value: None,
                full_name: Some("__main__.main.Return".to_string()),
                members: Some(HashMap::new()),
            },
        );
        identifiers.insert(
            String::from("__main__.main.SIZEOF_LOCALS"),
            Identifier {
                pc: None,
                type_: Some(String::from("const")),
                value: Some(Felt::zero()),
                full_name: None,
                members: None,
            },
        );

        assert_eq!(program.prime, PRIME_STR.to_string());
        assert_eq!(program.builtins, builtins);
        assert_eq!(program.data, data);
        assert_eq!(program.main, None);
        assert_eq!(program.identifiers, identifiers);
    }

    #[test]
    fn deserialize_program_constants_test() {
        let program = Program::from_file(
            Path::new("cairo_programs/manually_compiled/deserialize_constant_test.json"),
            Some("main"),
        )
        .expect("Failed to deserialize program");

        let constants = [
            ("__main__.compare_abs_arrays.SIZEOF_LOCALS", Felt::zero()),
            (
                "starkware.cairo.common.cairo_keccak.packed_keccak.ALL_ONES",
                felt_str!(
                    "3618502788666131106986593281521497120414687020801267626233049500247285301247"
                ),
            ),
            (
                "starkware.cairo.common.cairo_keccak.packed_keccak.BLOCK_SIZE",
                Felt::new(3),
            ),
            (
                "starkware.cairo.common.alloc.alloc.SIZEOF_LOCALS",
                felt_str!(
                    "-3618502788666131213697322783095070105623107215331596699973092056135872020481"
                ),
            ),
            (
                "starkware.cairo.common.uint256.SHIFT",
                felt_str!("340282366920938463463374607431768211456"),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<HashMap<_, _>>();

        assert_eq!(program.constants, constants);
    }

    #[test]
    fn default_program() {
        let program = Program {
            builtins: Vec::new(),
            prime: PRIME_STR.to_string(),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            start: None,
            end: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        assert_eq!(program, Program::default())
    }
}

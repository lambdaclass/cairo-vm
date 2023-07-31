use cairo_vm::{
    cairo_run::{cairo_run, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
};
use cairo_vm::serde::deserialize_program::{DebugInfo, Attribute, HintParams, ReferenceManager, Member};
use cairo_felt::Felt252;
use honggfuzz::fuzz;
use serde::{Serialize, Deserialize, Serializer};
use arbitrary::{self, Unstructured, Arbitrary};
use std::collections::HashMap;

const BUILTIN_NAMES: [&str; 9] = [
    "output", 
    "range_check", 
    "pedersen", 
    "ecdsa", 
    "keccak", 
    "bitwise", 
    "ec_op", 
    "poseidon", 
    "segment_arena"
];

const HEX_SYMBOLS: [&str; 16] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];

#[derive(Arbitrary, Serialize, Deserialize)]
struct ProgramJson {
    attributes: Vec::<Attribute>,
    #[arbitrary(with = arbitrary_builtins)]
    builtins: Vec::<String>,
    #[arbitrary(value = "0.11.0".to_string())]
    compiler_version: String,
    data: Vec<TextFelt>,
    debug_info: DebugInfo,
    #[arbitrary(with = prepend_main_identifier)] 
    identifiers: HashMap<String, TextIdentifier>,
    hints: HashMap<usize, Vec<HintParams>>,
    #[arbitrary(value = "__main__".to_string())]
    main_scope: String,
    #[arbitrary(value = "0x800000000000011000000000000000000000000000000000000000000000001".to_string())]
    prime: String,
    reference_manager: ReferenceManager
}

#[derive(Deserialize)]
struct TextFelt {
    value: String
}

#[derive(Serialize, Deserialize, Arbitrary)]
struct TextIdentifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pc: Option<usize>,
    #[serde(rename(serialize = "type"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    members: Option<HashMap<String, Member>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cairo_type: Option<String>,
}

impl<'a> Arbitrary<'a> for TextFelt {
    fn arbitrary(u: &mut Unstructured) -> arbitrary::Result<TextFelt> {
        let felt_size = 16;
        let mut digits = Vec::with_capacity(felt_size);
        for _ in 0..felt_size {
            digits.push(*u.choose(&HEX_SYMBOLS)?)
        }
        Ok(TextFelt { value: digits.join("") })
    }
}

impl Serialize for TextFelt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&format!("0x{}", self.value))
    }
}

fn arbitrary_builtins(u: &mut Unstructured) -> arbitrary::Result<Vec<String>> {
    let builtin_total = u.choose_index(BUILTIN_NAMES.len())?;
    let mut selected_builtins = Vec::new();

    for i in 0..=builtin_total {
        if u.ratio(2, 3)? {
            selected_builtins.push(BUILTIN_NAMES[i].to_string())
        }
    }

    Ok(selected_builtins)
}

fn prepend_main_identifier(_u: &mut Unstructured) -> arbitrary::Result<HashMap<String, TextIdentifier>> {
    let mut identifiers = HashMap::new();
    identifiers.insert(
        String::from("__main__.main"),
        TextIdentifier {
            pc: Some(0),
            type_: Some(String::from("function")),
            value: None,
            full_name: None, 
            members: None,
            cairo_type: None
        }
    );
    Ok(identifiers)
}

fn main() {
    loop {
        fuzz!(|data: (CairoRunConfig, ProgramJson)| {
            let (cairo_run_config, program_json) = data;
            match serde_json::to_string_pretty(&program_json) {
                Ok(program_raw) => {
                    let _ = cairo_run(
                        program_raw.as_bytes(),
                        &CairoRunConfig::default(),
                        &mut BuiltinHintProcessor::new_empty(),
                    );
                    let _ = cairo_run(
                        program_raw.as_bytes(),
                        &cairo_run_config,
                        &mut BuiltinHintProcessor::new_empty(),
                    );
                },
                Err(_) => {}
            }
        });
    }
}


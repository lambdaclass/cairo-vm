use serde::{Deserialize, Serialize};

use super::cairo_runner::ExecutionResources;
use crate::felt::Felt252;
use crate::serde::deserialize_program::BuiltinName;
use crate::stdlib::{collections::HashMap, prelude::*};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SegmentInfo {
    pub index: isize,
    pub size: usize,
}

impl From<(isize, usize)> for SegmentInfo {
    fn from(value: (isize, usize)) -> Self {
        SegmentInfo {
            index: value.0,
            size: value.1,
        }
    }
}

// A simplified version of Memory, without any additional data besides its elements
// Contains all addr-value pairs, ordered by index and offset
// Allows practical serialization + conversion between CairoPieMemory & Memory
pub type CairoPieMemory = Vec<((usize, usize), MaybeRelocatable)>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicMemoryPage {
    pub start: usize,
    pub size: usize,
}

// HashMap value based on starknet/core/os/output.cairo usage
pub type Attributes = HashMap<String, Vec<usize>>;
pub type Pages = HashMap<usize, PublicMemoryPage>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OutputBuiltinAdditionalData {
    pub pages: Pages,
    pub attributes: Attributes,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum BuiltinAdditionalData {
    // Contains verified addresses as contiguous index, value pairs
    Hash(Vec<Relocatable>),
    Output(OutputBuiltinAdditionalData),
    // Signatures are composed of (r, s) tuples
    Signature(HashMap<Relocatable, (Felt252, Felt252)>),
    None,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPie {
    pub metadata: CairoPieMetadata,
    pub memory: CairoPieMemory,
    pub execution_resources: ExecutionResources,
    pub additional_data: HashMap<String, BuiltinAdditionalData>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPieMetadata {
    pub program: StrippedProgram,
    pub program_segment: SegmentInfo,
    pub execution_segment: SegmentInfo,
    pub ret_fp_segment: SegmentInfo,
    pub ret_pc_segment: SegmentInfo,
    pub builtin_segments: HashMap<String, SegmentInfo>,
    pub extra_segments: Vec<SegmentInfo>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct StrippedProgram {
    #[serde(serialize_with = "program_data_serde::serialize")]
    pub data: Vec<MaybeRelocatable>,
    pub builtins: Vec<BuiltinName>,
    pub main: usize,
}

mod program_data_serde {
    use crate::types::relocatable::MaybeRelocatable;
    use felt::Felt252;
    use serde::{ser::SerializeSeq, Serialize, Serializer};

    struct Felt252Wrapper<'a>(&'a Felt252);

    impl<'a> Serialize for Felt252Wrapper<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // BigUint::from_bytes_be(&self.0.to_be_bytes()).serialize(serializer)
            serde_json::Number::from_string_unchecked(self.0.to_string()).serialize(serializer)
        }
    }

    pub fn serialize<S>(values: &[MaybeRelocatable], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq_serializer = serializer.serialize_seq(Some(values.len()))?;

        for value in values {
            match value {
                MaybeRelocatable::RelocatableValue(_) => todo!(),
                MaybeRelocatable::Int(x) => {
                    seq_serializer.serialize_element(&Felt252Wrapper(x))?;
                }
            };
        }

        seq_serializer.end()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        cairo_run::{cairo_run, CairoRunConfig},
        hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
        vm::runners::cairo_pie::{
            Attributes, BuiltinAdditionalData, OutputBuiltinAdditionalData, Pages,
        },
    };

    #[test]
    fn serialize_cairo_pie() {
        // Run the program
        let program_content = include_bytes!("../../../../cairo_programs/relocate_segments.json");
        let mut hint_processor = BuiltinHintProcessor::new_empty();
        let result = cairo_run(
            program_content,
            &CairoRunConfig {
                layout: "all_cairo",
                ..Default::default()
            },
            &mut hint_processor,
        );
        assert!(result.is_ok());
        let (runner, vm) = result.unwrap();
        // Obtain the pie
        let result = runner.get_cairo_pie(&vm);
        assert!(result.is_ok());
        let mut cairo_pie = result.unwrap();

        cairo_pie.additional_data.insert(
            "output_builtin".to_string(),
            BuiltinAdditionalData::Output(OutputBuiltinAdditionalData {
                pages: Pages::default(),
                attributes: Attributes::default(),
            }),
        );

        println!("{}", serde_json::to_string_pretty(&cairo_pie).unwrap());
    }
}

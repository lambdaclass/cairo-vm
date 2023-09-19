use super::cairo_runner::ExecutionResources;
use crate::{
    felt::Felt252,
    serde::deserialize_program::BuiltinName,
    stdlib::{collections::HashMap, prelude::*},
    types::relocatable::{MaybeRelocatable, Relocatable},
};
use serde::{Deserialize, Serialize};

const CAIRO_PIE_VERSION: &str = "1.1";

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
    #[serde(serialize_with = "serde_impl::serialize_memory")]
    pub memory: CairoPieMemory,
    pub execution_resources: ExecutionResources,
    pub additional_data: HashMap<String, BuiltinAdditionalData>,
    pub version: CairoPieVersion,
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
    #[serde(serialize_with = "serde_impl::serialize_program_data")]
    pub data: Vec<MaybeRelocatable>,
    pub builtins: Vec<BuiltinName>,
    pub main: usize,

    // Dummy field for serialization only.
    #[serde(serialize_with = "serde_impl::serialize_prime")]
    pub prime: (),
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPieVersion {
    // Dummy field for serialization only.
    #[serde(serialize_with = "serde_impl::serialize_version")]
    pub cairo_pie: (),
}

mod serde_impl {
    use super::CAIRO_PIE_VERSION;
    use crate::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        utils::CAIRO_PRIME,
    };
    use felt::Felt252;
    use num_bigint::BigUint;
    use num_traits::Num;
    use serde::{
        ser::{SerializeSeq, SerializeTuple},
        Serialize, Serializer,
    };

    const ADDR_BYTE_LEN: usize = 8;
    const FIELD_BYTE_LEN: usize = 32;
    const ADDR_BASE: usize = 0x8000000000000000; // 2 ** (8 * ADDR_BYTE_LEN - 1)
    const OFFSET_BASE: usize = 0x800000000000; // 2 ** OFFSET_BIT_LEN
    const RELOCATE_BASE: &str = "8000000000000000000000000000000000000000000000000000000000000000"; // 2 ** (8 * FIELD_BYTE_LEN - 1)

    struct Felt252Wrapper<'a>(&'a Felt252);
    struct RelocatableWrapper<'a>(&'a Relocatable);

    impl<'a> Serialize for Felt252Wrapper<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            #[cfg(any(target_arch = "wasm32", no_std, not(feature = "std")))]
            use crate::alloc::string::ToString;

            // Note: This uses an API intended only for testing.
            serde_json::Number::from_string_unchecked(self.0.to_string()).serialize(serializer)
        }
    }

    impl<'a> Serialize for RelocatableWrapper<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut tuple_serializer = serializer.serialize_tuple(2)?;

            tuple_serializer.serialize_element(&self.0.segment_index)?;
            tuple_serializer.serialize_element(&self.0.offset)?;

            tuple_serializer.end()
        }
    }

    pub fn serialize_program_data<S>(
        values: &[MaybeRelocatable],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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

    pub fn serialize_memory<S>(
        values: &[((usize, usize), MaybeRelocatable)],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO: update current test, add new test
        // Missing segment and memory holes can be ignored
        // as they can be inferred by the address on the prover side
        let mem_cap = values.len() * ADDR_BYTE_LEN + values.len() * FIELD_BYTE_LEN;
        let mut res = Vec::with_capacity(mem_cap);

        for ((segment, offset), value) in values.iter() {
            match value {
                // Serializes RelocatableValue as(little endian):
                // 1bit |   SEGMENT_BITS |   OFFSET_BITS
                // 1    |     segment    |   offset
                MaybeRelocatable::RelocatableValue(rel_val) => {
                    let mem_addr = ADDR_BASE + *segment * OFFSET_BASE + *offset;

                    let reloc_base = BigUint::from_str_radix(RELOCATE_BASE, 16)
                        .map_err(|_| serde::ser::Error::custom("invalid int str"))?;
                    let reloc_value = reloc_base
                        + BigUint::from(rel_val.segment_index as usize)
                            * BigUint::from(OFFSET_BASE)
                        + BigUint::from(rel_val.offset);
                    res.extend_from_slice(mem_addr.to_le_bytes().as_ref());
                    res.extend_from_slice(reloc_value.to_bytes_le().as_ref());
                }
                // Serializes Int as(little endian):
                // 1bit | Num
                // 0    | num
                MaybeRelocatable::Int(data_val) => {
                    let mem_addr = ADDR_BASE + *segment * OFFSET_BASE + *offset;
                    res.extend_from_slice(mem_addr.to_le_bytes().as_ref());
                    res.extend_from_slice(data_val.to_le_bytes().as_ref());
                }
            };
        }

        serializer.serialize_str(
            res.iter()
                .map(|b| format!("{:x}", b))
                .collect::<String>()
                .as_str(),
        )
    }

    pub fn serialize_prime<S>(_value: &(), serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[cfg(any(target_arch = "wasm32", no_std, not(feature = "std")))]
        use crate::alloc::string::ToString;

        // Note: This uses an API intended only for testing.
        serde_json::Number::from_string_unchecked(CAIRO_PRIME.to_string()).serialize(serializer)
    }

    pub fn serialize_version<S>(_value: &(), serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(CAIRO_PIE_VERSION)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialize_cairo_pie_memory() {
        #[derive(Serialize)]
        struct MemoryWrapper(
            #[serde(serialize_with = "serde_impl::serialize_memory")] CairoPieMemory,
        );

        let memory = MemoryWrapper(vec![
            ((1, 0), MaybeRelocatable::Int(10.into())),
            ((1, 1), MaybeRelocatable::Int(11.into())),
            ((1, 4), MaybeRelocatable::Int(12.into())),
            ((1, 8), MaybeRelocatable::RelocatableValue((1, 2).into())),
            ((2, 0), MaybeRelocatable::RelocatableValue((3, 4).into())),
            ((4, 8), MaybeRelocatable::RelocatableValue((5, 6).into())),
        ]);

        assert_eq!(
            serde_json::to_value(memory).unwrap(),
            json!([
                (),
                [10, 11, (), (), 12, (), (), (), [1, 2]],
                [[3, 4,]],
                (),
                [(), (), (), (), (), (), (), (), [5, 6]]
            ]),
        );
    }
}

use super::cairo_runner::ExecutionResources;
use crate::{
    felt::Felt252,
    serde::deserialize_program::BuiltinName,
    stdlib::{collections::HashMap, prelude::*},
    types::relocatable::{MaybeRelocatable, Relocatable},
};
use serde::{Deserialize, Serialize};

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
    use crate::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        utils::CAIRO_PRIME,
    };
    #[cfg(any(target_arch = "wasm32", no_std, not(feature = "std")))]
    use alloc::collections::{btree_map::Entry, BTreeMap};
    use felt::Felt252;
    use serde::{
        ser::{SerializeSeq, SerializeTuple},
        Serialize, Serializer,
    };
    #[cfg(not(any(target_arch = "wasm32", no_std, not(feature = "std"))))]
    use std::collections::{btree_map::Entry, BTreeMap};

    struct Felt252Wrapper<'a>(&'a Felt252);
    struct RelocatableWrapper<'a>(&'a Relocatable);

    struct MissingSegment;

    struct MemoryData<'a>(&'a BTreeMap<usize, &'a MaybeRelocatable>);
    struct MemoryHole;

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

    impl Serialize for MissingSegment {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_none()
        }
    }

    impl<'a> Serialize for MemoryData<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq_serializer = serializer.serialize_seq(Some(
                self.0
                    .last_key_value()
                    .map(|x| *x.0 + 1)
                    .unwrap_or_default(),
            ))?;

            let mut last_offset = None;
            for (offset, value) in self.0.iter() {
                // Serialize memory holes as `None`.
                for _ in last_offset.map(|x| x + 1).unwrap_or_default()..*offset {
                    seq_serializer.serialize_element(&MemoryHole)?;
                }

                // Update the last offset to check for memory holes after itself.
                last_offset = Some(*offset);

                // Serialize the data.
                match value {
                    MaybeRelocatable::RelocatableValue(x) => {
                        seq_serializer.serialize_element(&RelocatableWrapper(x))?
                    }
                    MaybeRelocatable::Int(x) => {
                        seq_serializer.serialize_element(&Felt252Wrapper(x))?
                    }
                }
            }

            seq_serializer.end()
        }
    }

    impl Serialize for MemoryHole {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_none()
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
        let mut memory = BTreeMap::new();
        for value in values {
            let segment_entry = match memory.entry(value.0 .0) {
                Entry::Vacant(x) => x.insert(BTreeMap::new()),
                Entry::Occupied(x) => x.into_mut(),
            };

            segment_entry.insert(value.0 .1, &value.1);
        }

        let mut seq_serializer = serializer.serialize_seq(Some(
            memory
                .last_entry()
                .map(|x| *x.key() + 1)
                .unwrap_or_default(),
        ))?;

        let mut last_segment = None;
        for (segment_idx, segment_data) in memory {
            // Serialize missing segments as `None`.
            for _ in last_segment.map(|x| x + 1).unwrap_or_default()..segment_idx {
                seq_serializer.serialize_element(&MissingSegment)?;
            }

            // Update the last segment to check for missing segments after itself.
            last_segment = Some(segment_idx);

            // Serialize the data.
            seq_serializer.serialize_element(&MemoryData(&segment_data))?;
        }

        seq_serializer.end()
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
        serializer.serialize_str("1.1")
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

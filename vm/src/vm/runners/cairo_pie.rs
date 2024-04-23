use super::cairo_runner::ExecutionResources;
use crate::stdlib::prelude::{String, Vec};
use crate::types::builtin_name::BuiltinName;
use crate::{
    stdlib::{collections::HashMap, prelude::*},
    types::relocatable::{MaybeRelocatable, Relocatable},
    Felt252,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use {
    std::{fs::File, io::Write, path::Path},
    zip::ZipWriter,
};

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
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPieMemory(
    #[serde(serialize_with = "serde_impl::serialize_memory")]
    pub  Vec<((usize, usize), MaybeRelocatable)>,
);

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
    #[serde(with = "serde_impl::hash_additional_data")]
    Hash(Vec<Relocatable>),
    Output(OutputBuiltinAdditionalData),
    // Signatures are composed of (r, s) tuples
    #[serde(with = "serde_impl::signature_additional_data")]
    Signature(HashMap<Relocatable, (Felt252, Felt252)>),
    None,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPieAdditionalData(
    #[serde(with = "crate::types::builtin_name::serde_generic_map_impl")]
    pub  HashMap<BuiltinName, BuiltinAdditionalData>,
);

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPie {
    pub metadata: CairoPieMetadata,
    pub memory: CairoPieMemory,
    pub execution_resources: ExecutionResources,
    pub additional_data: CairoPieAdditionalData,
    pub version: CairoPieVersion,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPieMetadata {
    pub program: StrippedProgram,
    pub program_segment: SegmentInfo,
    pub execution_segment: SegmentInfo,
    pub ret_fp_segment: SegmentInfo,
    pub ret_pc_segment: SegmentInfo,
    #[serde(serialize_with = "serde_impl::serialize_builtin_segments")]
    pub builtin_segments: HashMap<BuiltinName, SegmentInfo>,
    pub extra_segments: Vec<SegmentInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StrippedProgram {
    #[serde(with = "serde_impl::program_data")]
    pub data: Vec<MaybeRelocatable>,
    pub builtins: Vec<BuiltinName>,
    pub main: usize,
    // Dummy field
    #[serde(with = "serde_impl::prime")]
    pub prime: (),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CairoPieVersion {
    // Dummy field
    #[serde(with = "serde_impl::version")]
    pub cairo_pie: (),
}

impl CairoPie {
    #[cfg(feature = "std")]
    pub fn write_zip_file(&self, file_path: &Path) -> Result<(), std::io::Error> {
        let file = File::create(file_path)?;
        let mut zip_writer = ZipWriter::new(file);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip_writer.start_file("version.json", options)?;
        zip_writer.write_all(serde_json::to_string(&self.version)?.as_bytes())?;
        zip_writer.start_file("metadata.json", options)?;
        zip_writer.write_all(serde_json::to_string(&self.metadata)?.as_bytes())?;
        zip_writer.start_file("memory.bin", options)?;
        zip_writer.write_all(&self.memory.to_bytes())?;
        zip_writer.start_file("additional_data.json", options)?;
        zip_writer.write_all(serde_json::to_string(&self.additional_data)?.as_bytes())?;
        zip_writer.start_file("execution_resources.json", options)?;
        zip_writer.write_all(serde_json::to_string(&self.execution_resources)?.as_bytes())?;
        zip_writer.finish()?;
        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn read_zip_file(file_path: &Path) -> Result<CairoPie, std::io::Error> {
        use std::io::Read;
        use zip::ZipArchive;

        let file = File::open(file_path)?;
        let mut zip_reader = ZipArchive::new(file)?;

        let mut version = vec![];
        zip_reader
            .by_name("version.json")?
            .read_to_end(&mut version)?;
        let version: CairoPieVersion = serde_json::from_slice(&version)?;

        let mut metadata = vec![];
        zip_reader
            .by_name("metadata.json")?
            .read_to_end(&mut metadata)?;
        let metadata: CairoPieMetadata = serde_json::from_slice(&metadata)?;

        let mut memory = vec![];
        zip_reader.by_name("memory.bin")?.read_to_end(&mut memory)?;
        let memory = CairoPieMemory::from_bytes(&memory)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;

        let mut execution_resources = vec![];
        zip_reader
            .by_name("execution_resources.json")?
            .read_to_end(&mut execution_resources)?;
        let execution_resources: ExecutionResources = serde_json::from_slice(&execution_resources)?;

        let mut additional_data = vec![];
        zip_reader
            .by_name("additional_data.json")?
            .read_to_end(&mut additional_data)?;
        let additional_data: CairoPieAdditionalData = serde_json::from_slice(&additional_data)?;

        Ok(CairoPie {
            metadata,
            memory,
            execution_resources,
            additional_data,
            version,
        })
    }
}

pub(super) mod serde_impl {
    use crate::stdlib::collections::HashMap;
    use crate::types::builtin_name::BuiltinName;
    use num_integer::Integer;
    use num_traits::Num;
    use serde::ser::SerializeMap;

    use super::CAIRO_PIE_VERSION;
    use super::{CairoPieMemory, SegmentInfo};
    #[cfg(any(target_arch = "wasm32", no_std, not(feature = "std")))]
    use crate::alloc::string::ToString;
    use crate::stdlib::prelude::{String, Vec};
    use crate::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        utils::CAIRO_PRIME,
        Felt252,
    };
    use num_bigint::BigUint;
    use serde::{de::Error, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

    pub const ADDR_BYTE_LEN: usize = 8;
    pub const FIELD_BYTE_LEN: usize = 32;
    pub const CELL_BYTE_LEN: usize = ADDR_BYTE_LEN + FIELD_BYTE_LEN;
    pub const ADDR_BASE: u64 = 0x8000000000000000; // 2 ** (8 * ADDR_BYTE_LEN - 1)
    pub const OFFSET_BASE: u64 = 0x800000000000; // 2 ** OFFSET_BIT_LEN
    pub const RELOCATE_BASE: &str =
        "8000000000000000000000000000000000000000000000000000000000000000"; // 2 ** (8 * FIELD_BYTE_LEN - 1)

    pub(crate) struct Felt252Wrapper<'a>(&'a Felt252);

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

    pub mod version {
        use super::*;

        pub fn serialize<S>(_value: &(), serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(CAIRO_PIE_VERSION)
        }

        pub fn deserialize<'de, D>(d: D) -> Result<(), D::Error>
        where
            D: Deserializer<'de>,
        {
            let version = String::deserialize(d)?;

            if version != CAIRO_PIE_VERSION {
                Err(D::Error::custom("Invalid cairo_pie version"))
            } else {
                Ok(())
            }
        }
    }

    pub mod program_data {
        use super::*;
        use crate::types::relocatable::MaybeRelocatable;

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

        pub fn deserialize<'de, D>(d: D) -> Result<Vec<MaybeRelocatable>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let numbers = Vec::<serde_json::Number>::deserialize(d)?;
            numbers
                .into_iter()
                .map(|n| Felt252::from_dec_str(n.as_str()).map(|f| MaybeRelocatable::from(f)))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| D::Error::custom("Failed to deserilaize Felt252 value"))
        }
    }

    pub mod prime {
        use super::*;

        pub fn serialize<S>(_value: &(), serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Note: This uses an API intended only for testing.
            serde_json::Number::from_string_unchecked(CAIRO_PRIME.to_string()).serialize(serializer)
        }

        pub fn deserialize<'de, D>(d: D) -> Result<(), D::Error>
        where
            D: Deserializer<'de>,
        {
            let prime = serde_json::Number::deserialize(d)?;

            if prime.as_str() != CAIRO_PRIME.to_string() {
                Err(D::Error::custom("Invalid prime"))
            } else {
                Ok(())
            }
        }
    }

    pub fn serialize_memory<S>(
        values: &[((usize, usize), MaybeRelocatable)],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Missing segment and memory holes can be ignored
        // as they can be inferred by the address on the prover side
        let mem_cap = values.len() * ADDR_BYTE_LEN + values.len() * FIELD_BYTE_LEN;
        let mut res = Vec::with_capacity(mem_cap);

        for ((segment, offset), value) in values.iter() {
            let mem_addr = ADDR_BASE + *segment as u64 * OFFSET_BASE + *offset as u64;
            res.extend_from_slice(mem_addr.to_le_bytes().as_ref());
            match value {
                // Serializes RelocatableValue(little endian):
                // 1bit |   SEGMENT_BITS |   OFFSET_BITS
                // 1    |     segment    |   offset
                MaybeRelocatable::RelocatableValue(rel_val) => {
                    let reloc_base = BigUint::from_str_radix(RELOCATE_BASE, 16)
                        .map_err(|_| serde::ser::Error::custom("invalid relocation base str"))?;
                    let reloc_value = reloc_base
                        + BigUint::from(rel_val.segment_index as usize)
                            * BigUint::from(OFFSET_BASE)
                        + BigUint::from(rel_val.offset);
                    res.extend_from_slice(reloc_value.to_bytes_le().as_ref());
                }
                // Serializes Int(little endian):
                // 1bit | Num
                // 0    | num
                MaybeRelocatable::Int(data_val) => {
                    res.extend_from_slice(data_val.to_bytes_le().as_ref());
                }
            };
        }

        let string = res
            .iter()
            .fold(String::new(), |string, b| string + &format!("{:02x}", b));

        serializer.serialize_str(&string)
    }

    impl CairoPieMemory {
        pub fn to_bytes(&self) -> Vec<u8> {
            // Missing segment and memory holes can be ignored
            // as they can be inferred by the address on the prover side
            let values = &self.0;
            let mem_cap = values.len() * ADDR_BYTE_LEN + values.len() * FIELD_BYTE_LEN;
            let mut res = Vec::with_capacity(mem_cap);

            for ((segment, offset), value) in values.iter() {
                let mem_addr = ADDR_BASE + *segment as u64 * OFFSET_BASE + *offset as u64;
                res.extend_from_slice(mem_addr.to_le_bytes().as_ref());
                match value {
                    // Serializes RelocatableValue(little endian):
                    // 1bit |   SEGMENT_BITS |   OFFSET_BITS
                    // 1    |     segment    |   offset
                    MaybeRelocatable::RelocatableValue(rel_val) => {
                        let reloc_base = BigUint::from_str_radix(RELOCATE_BASE, 16).unwrap();
                        let reloc_value = reloc_base
                            + BigUint::from(rel_val.segment_index as usize)
                                * BigUint::from(OFFSET_BASE)
                            + BigUint::from(rel_val.offset);
                        res.extend_from_slice(reloc_value.to_bytes_le().as_ref());
                    }
                    // Serializes Int(little endian):
                    // 1bit | Num
                    // 0    | num
                    MaybeRelocatable::Int(data_val) => {
                        res.extend_from_slice(data_val.to_bytes_le().as_ref());
                    }
                };
            }
            res
        }

        pub fn from_bytes(bytes: &[u8]) -> Option<CairoPieMemory> {
            if !bytes.len().is_multiple_of(&CELL_BYTE_LEN) {
                return None;
            }

            let relocatable_from_bytes = |bytes: [u8; 8]| -> (usize, usize) {
                const N_SEGMENT_BITS: usize = 16;
                const N_OFFSET_BITS: usize = 47;
                const SEGMENT_MASK: u64 = ((1 << N_SEGMENT_BITS) - 1) << N_OFFSET_BITS;
                const OFFSET_MASK: u64 = (1 << N_OFFSET_BITS) - 1;

                let addr = u64::from_le_bytes(bytes);
                let segment = (addr & SEGMENT_MASK) >> N_OFFSET_BITS;
                let offset = addr & OFFSET_MASK;
                (segment as usize, offset as usize)
            };

            let mut res = vec![];
            for cell_bytes in bytes.chunks(CELL_BYTE_LEN) {
                let addr = relocatable_from_bytes(cell_bytes[0..ADDR_BYTE_LEN].try_into().ok()?);
                let field_bytes = &cell_bytes[ADDR_BYTE_LEN..CELL_BYTE_LEN];
                // Check the last bit to determine if it is a Relocatable or Felt value
                let value = if (field_bytes[field_bytes.len() - 1] & 0x80) != 0 {
                    let (segment, offset) =
                        relocatable_from_bytes(field_bytes[0..ADDR_BYTE_LEN].try_into().ok()?);
                    MaybeRelocatable::from((segment as isize, offset))
                } else {
                    MaybeRelocatable::from(Felt252::from_bytes_le_slice(field_bytes))
                };
                res.push((addr, value));
            }

            Some(CairoPieMemory(res))
        }
    }

    pub mod signature_additional_data {
        use serde_json::Number;

        use super::*;

        pub fn serialize<S>(
            values: &HashMap<Relocatable, (Felt252, Felt252)>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq_serializer = serializer.serialize_seq(Some(values.len()))?;

            for (key, (x, y)) in values {
                seq_serializer.serialize_element(&[
                    [
                        Felt252Wrapper(&Felt252::from(key.segment_index)),
                        Felt252Wrapper(&Felt252::from(key.offset)),
                    ],
                    [Felt252Wrapper(x), Felt252Wrapper(y)],
                ])?;
            }
            seq_serializer.end()
        }

        pub fn deserialize<'de, D>(
            d: D,
        ) -> Result<HashMap<Relocatable, (Felt252, Felt252)>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let number_map = Vec::<((Number, Number), (Number, Number))>::deserialize(d)?;
            let mut res = HashMap::new();
            for ((index, offset), (r, s)) in number_map.into_iter() {
                let addr = Relocatable::from((
                    index.as_u64().ok_or(D::Error::custom("Invalid address"))? as isize,
                    offset.as_u64().ok_or(D::Error::custom("Invalid address"))? as usize,
                ));
                let r = Felt252::from_dec_str(r.as_str())
                    .map_err(|_| D::Error::custom("Invalid Felt252 value"))?;
                let s = Felt252::from_dec_str(s.as_str())
                    .map_err(|_| D::Error::custom("Invalid Felt252 value"))?;
                res.insert(addr, (r, s));
            }
            Ok(res)
        }
    }

    pub mod hash_additional_data {
        use super::*;
        pub fn serialize<S>(values: &[Relocatable], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq_serializer: <S as Serializer>::SerializeSeq =
                serializer.serialize_seq(Some(values.len()))?;

            for value in values {
                seq_serializer.serialize_element(&[value.segment_index, value.offset as isize])?;
            }

            seq_serializer.end()
        }

        pub fn deserialize<'de, D>(d: D) -> Result<Vec<Relocatable>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let tuples = Vec::<(usize, usize)>::deserialize(d)?;
            Ok(tuples
                .into_iter()
                .map(|(x, y)| Relocatable::from((x as isize, y)))
                .collect())
        }
    }

    pub fn serialize_builtin_segments<S>(
        values: &HashMap<BuiltinName, SegmentInfo>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map_serializer = serializer.serialize_map(Some(values.len()))?;
        const BUILTIN_ORDERED_LIST: &[BuiltinName] = &[
            BuiltinName::output,
            BuiltinName::pedersen,
            BuiltinName::range_check,
            BuiltinName::ecdsa,
            BuiltinName::bitwise,
            BuiltinName::ec_op,
            BuiltinName::keccak,
            BuiltinName::poseidon,
        ];

        for name in BUILTIN_ORDERED_LIST {
            if let Some(info) = values.get(name) {
                map_serializer.serialize_entry(name, info)?
            }
        }
        map_serializer.end()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        cairo_run::CairoRunConfig,
        hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    };
    use rstest::rstest;

    use super::*;

    #[test]
    fn serialize_cairo_pie_memory() {
        let addrs = [
            ((1, 0), "0000000000800080"),
            ((1, 1), "0100000000800080"),
            ((1, 4), "0400000000800080"),
            ((1, 8), "0800000000800080"),
            ((2, 0), "0000000000000180"),
            ((5, 8), "0800000000800280"),
        ];

        let memory = CairoPieMemory(vec![
            (addrs[0].0, MaybeRelocatable::Int(1234.into())),
            (addrs[1].0, MaybeRelocatable::Int(11.into())),
            (addrs[2].0, MaybeRelocatable::Int(12.into())),
            (
                addrs[3].0,
                MaybeRelocatable::RelocatableValue((1, 2).into()),
            ),
            (
                addrs[4].0,
                MaybeRelocatable::RelocatableValue((3, 4).into()),
            ),
            (
                addrs[5].0,
                MaybeRelocatable::RelocatableValue((5, 6).into()),
            ),
        ]);

        let mem = serde_json::to_value(memory).unwrap();
        let mem_str = mem.as_str().unwrap();
        let shift_len = (serde_impl::ADDR_BYTE_LEN + serde_impl::FIELD_BYTE_LEN) * 2;
        let shift_field = serde_impl::FIELD_BYTE_LEN * 2;
        let shift_addr = serde_impl::ADDR_BYTE_LEN * 2;

        // Serializes Address 8 Byte(little endian):
        for (i, expected_addr) in addrs.into_iter().enumerate() {
            let shift = shift_len * i;
            assert_eq!(
                &mem_str[shift..shift + shift_addr],
                expected_addr.1,
                "addr mismatch({i}): {mem_str:?}",
            );
        }

        // Serializes Int(little endian):
        // 1bit | Num
        // 0    | num
        assert_eq!(
            &mem_str[shift_addr..shift_addr + shift_field],
            "d204000000000000000000000000000000000000000000000000000000000000",
            "value mismatch: {mem_str:?}",
        );
        // Serializes RelocatableValue(little endian):
        // 1bit |   SEGMENT_BITS |   OFFSET_BITS
        // 1    |     segment    |   offset
        let shift_first_relocatable = shift_len * 3 + shift_addr;
        assert_eq!(
            &mem_str[shift_first_relocatable..shift_first_relocatable + shift_field],
            "0200000000800000000000000000000000000000000000000000000000000080",
            "value mismatch: {mem_str:?}",
        );
    }

    #[rstest]
    #[cfg(feature = "std")]
    #[case(include_bytes!("../../../../cairo_programs/fibonacci.json"), "fibonacci")]
    #[case(include_bytes!("../../../../cairo_programs/integration.json"), "integration")]
    #[case(include_bytes!("../../../../cairo_programs/common_signature.json"), "signature")]
    #[case(include_bytes!("../../../../cairo_programs/relocate_segments.json"), "relocate")]
    #[case(include_bytes!("../../../../cairo_programs/ec_op.json"), "ec_op")]
    #[case(include_bytes!("../../../../cairo_programs/bitwise_output.json"), "bitwise")]
    fn read_write_pie_zip(#[case] program_content: &[u8], #[case] identifier: &str) {
        use crate::types::layout_name::LayoutName;
        // Run a program to obtain the CairoPie
        let cairo_pie = {
            let cairo_run_config = CairoRunConfig {
                layout: LayoutName::starknet_with_keccak,
                ..Default::default()
            };
            let (runner, vm) = crate::cairo_run::cairo_run(
                program_content,
                &cairo_run_config,
                &mut BuiltinHintProcessor::new_empty(),
            )
            .unwrap();
            runner.get_cairo_pie(&vm).unwrap()
        };
        // Serialize the CairoPie into a zip file
        let filename = format!("temp_file_{}", identifier); // Identifier used to avoid name clashes
        let file_path = Path::new(&filename);
        cairo_pie.write_zip_file(file_path).unwrap();
        // Deserialize the zip file
        let deserialized_pie = CairoPie::read_zip_file(file_path).unwrap();
        // Check that both pies are equal
        assert_eq!(cairo_pie, deserialized_pie);
    }
}

use super::cairo_runner::ExecutionResources;
use crate::stdlib::prelude::{String, Vec};
use crate::types::builtin_name::BuiltinName;
use crate::vm::errors::cairo_pie_errors::CairoPieValidationError;
use crate::{
    stdlib::{collections::HashMap, prelude::*},
    types::relocatable::{MaybeRelocatable, Relocatable},
    Felt252,
};
use num_traits::{One, Zero};
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
    #[serde(serialize_with = "serde_impl::serialize_hash_additional_data")]
    Hash(Vec<Relocatable>),
    Output(OutputBuiltinAdditionalData),
    // Signatures are composed of (r, s) tuples
    #[serde(serialize_with = "serde_impl::serialize_signature_additional_data")]
    Signature(HashMap<Relocatable, (Felt252, Felt252)>),
    None,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
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

    /// Check that self is a valid Cairo PIE
    pub fn run_validity_checks(&self) -> Result<(), CairoPieValidationError> {
        self.metadata.run_validity_checks()?;
        self.run_memory_validity_checks()?;
        if self.execution_resources.builtin_instance_counter.len()
            != self.metadata.program.builtins.len()
            || !self.metadata.program.builtins.iter().all(|b| {
                self.execution_resources
                    .builtin_instance_counter
                    .contains_key(b)
            })
        {
            return Err(CairoPieValidationError::BuiltinListVsSegmentsMismatch);
        }
        Ok(())
    }

    fn run_memory_validity_checks(&self) -> Result<(), CairoPieValidationError> {
        let mut segment_sizes = vec![
            &self.metadata.program_segment,
            &self.metadata.execution_segment,
            &self.metadata.ret_fp_segment,
            &self.metadata.ret_pc_segment,
        ];
        segment_sizes.extend(self.metadata.builtin_segments.values());
        segment_sizes.extend(self.metadata.extra_segments.iter());
        let segment_sizes: HashMap<isize, usize> =
            HashMap::from_iter(segment_sizes.iter().map(|si| (si.index, si.size)));

        let validate_addr = |addr: Relocatable| -> Result<(), CairoPieValidationError> {
            if !segment_sizes
                .get(&addr.segment_index)
                .is_some_and(|size| addr.offset <= *size)
            {
                return Err(CairoPieValidationError::InvalidAddress);
            }
            Ok(())
        };

        for ((si, so), value) in self.memory.0.iter() {
            validate_addr((*si as isize, *so).into())?;
            if let MaybeRelocatable::RelocatableValue(val) = value {
                validate_addr(*val)?;
            }
        }
        Ok(())
    }

    /// Checks that the pie received is identical to self, skipping the fields execution_resources.n_steps, and additional_data[pedersen]
    /// Stricter runs check more Pedersen addresses leading to different address lists
    pub fn check_pie_compatibility(&self, pie: &CairoPie) -> Result<(), CairoPieValidationError> {
        if self.metadata != pie.metadata {
            return Err(CairoPieValidationError::DiffMetadata);
        }
        if self.memory != pie.memory {
            return Err(CairoPieValidationError::DiffMemory);
        }
        if self.execution_resources.n_steps != pie.execution_resources.n_steps
            || self.execution_resources.builtin_instance_counter
                != pie.execution_resources.builtin_instance_counter
        {
            return Err(CairoPieValidationError::DiffExecutionResources);
        }
        if self.additional_data.0.len() != pie.additional_data.0.len() {
            return Err(CairoPieValidationError::DiffAdditionalData);
        }
        for (name, data) in self.additional_data.0.iter() {
            if !pie.additional_data.0.get(name).is_some_and(|d| d == data) {
                return Err(CairoPieValidationError::DiffAdditionalDataForBuiltin(*name));
            }
        }
        Ok(())
    }
}

impl CairoPieMetadata {
    pub(crate) fn run_validity_checks(&self) -> Result<(), CairoPieValidationError> {
        if self.program.main > self.program.data.len() {
            return Err(CairoPieValidationError::InvalidMainAddress);
        }
        if self.program.data.len() != self.program_segment.size {
            return Err(CairoPieValidationError::ProgramLenVsSegmentSizeMismatch);
        }
        if self.builtin_segments.len() != self.program.builtins.len()
            || !self
                .program
                .builtins
                .iter()
                .all(|b| self.builtin_segments.contains_key(b))
        {
            return Err(CairoPieValidationError::BuiltinListVsSegmentsMismatch);
        }
        if !self.ret_fp_segment.size.is_zero() {
            return Err(CairoPieValidationError::InvalidRetFpSegmentSize);
        }
        if !self.ret_pc_segment.size.is_zero() {
            return Err(CairoPieValidationError::InvalidRetPcSegmentSize);
        }
        self.validate_segment_order()
    }

    fn validate_segment_order(&self) -> Result<(), CairoPieValidationError> {
        if !self.program_segment.index.is_zero() {
            return Err(CairoPieValidationError::InvalidProgramSegmentIndex);
        }
        if !self.execution_segment.index.is_one() {
            return Err(CairoPieValidationError::InvalidExecutionSegmentIndex);
        }
        for (i, builtin_name) in self.program.builtins.iter().enumerate() {
            // We can safely index as run_validity_checks already ensures that the keys match
            if self.builtin_segments[builtin_name].index != 2 + i as isize {
                return Err(CairoPieValidationError::InvalidBuiltinSegmentIndex(
                    *builtin_name,
                ));
            }
        }
        let n_builtins = self.program.builtins.len() as isize;
        if self.ret_fp_segment.index != n_builtins + 2 {
            return Err(CairoPieValidationError::InvalidRetFpSegmentIndex);
        }
        if self.ret_pc_segment.index != n_builtins + 3 {
            return Err(CairoPieValidationError::InvalidRetPcSegmentIndex);
        }
        for (i, segment) in self.extra_segments.iter().enumerate() {
            if segment.index != 4 + n_builtins + i as isize {
                return Err(CairoPieValidationError::InvalidExtraSegmentIndex);
            }
        }
        Ok(())
    }
}

mod serde_impl {
    use crate::stdlib::collections::HashMap;
    use crate::types::builtin_name::BuiltinName;
    use num_traits::Num;
    use serde::ser::SerializeMap;

    use super::{CairoPieMemory, SegmentInfo, CAIRO_PIE_VERSION};
    use crate::stdlib::prelude::{String, Vec};
    use crate::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        utils::CAIRO_PRIME,
        Felt252,
    };
    use num_bigint::BigUint;
    use serde::{ser::SerializeSeq, Serialize, Serializer};

    pub const ADDR_BYTE_LEN: usize = 8;
    pub const FIELD_BYTE_LEN: usize = 32;
    pub const ADDR_BASE: u64 = 0x8000000000000000; // 2 ** (8 * ADDR_BYTE_LEN - 1)
    pub const OFFSET_BASE: u64 = 0x800000000000; // 2 ** OFFSET_BIT_LEN
    pub const RELOCATE_BASE: &str =
        "8000000000000000000000000000000000000000000000000000000000000000"; // 2 ** (8 * FIELD_BYTE_LEN - 1)

    struct Felt252Wrapper<'a>(&'a Felt252);

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

    pub fn serialize_signature_additional_data<S>(
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

    pub fn serialize_hash_additional_data<S>(
        values: &[Relocatable],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq_serializer = serializer.serialize_seq(Some(values.len()))?;

        for value in values {
            seq_serializer.serialize_element(&[value.segment_index, value.offset as isize])?;
        }

        seq_serializer.end()
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
}

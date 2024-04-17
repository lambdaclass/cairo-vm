use serde::{Deserialize, Serialize};

#[cfg(all(feature = "arbitrary", feature = "std"))]
use arbitrary::{self, Arbitrary};

// This enum is used to deserialize program builtins into &str and catch non-valid names
#[cfg_attr(all(feature = "arbitrary", feature = "std"), derive(Arbitrary))]
#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum BuiltinName {
    output,
    range_check,
    pedersen,
    ecdsa,
    keccak,
    bitwise,
    ec_op,
    poseidon,
    segment_arena,
    range_check96,
    add_mod,
    mul_mod,
}

impl BuiltinName {
    pub fn to_str_with_suffix(&self) -> &'static str {
        match self {
            BuiltinName::output => "output_builtin",
            BuiltinName::range_check => "range_check_builtin",
            BuiltinName::pedersen => "pedersen_builtin",
            BuiltinName::ecdsa => "ecdsa_builtin",
            BuiltinName::keccak => "keccak_builtin",
            BuiltinName::bitwise => "bitwise_builtin",
            BuiltinName::ec_op => "ec_op_builtin",
            BuiltinName::poseidon => "poseidon_builtin",
            BuiltinName::segment_arena => "segment_arena_builtin",
            BuiltinName::range_check96 => "range_check96_builtin",
            BuiltinName::add_mod => "add_mod_builtin",
            BuiltinName::mul_mod => "mul_mod_builtin",
        }
    }
}

impl BuiltinName {
    pub fn to_str(&self) -> &'static str {
        match self {
            BuiltinName::output => "output",
            BuiltinName::range_check => "range_check",
            BuiltinName::pedersen => "pedersen",
            BuiltinName::ecdsa => "ecdsa",
            BuiltinName::keccak => "keccak",
            BuiltinName::bitwise => "bitwise",
            BuiltinName::ec_op => "ec_op",
            BuiltinName::poseidon => "poseidon",
            BuiltinName::segment_arena => "segment_arena",
            BuiltinName::range_check96 => "range_check96",
            BuiltinName::add_mod => "add_mod",
            BuiltinName::mul_mod => "mul_mod",
        }
    }
}

impl core::fmt::Display for BuiltinName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.to_str_with_suffix().fmt(f)
    }
}

pub(crate) mod serde_impl {
    use super::BuiltinName;
    use serde::{Serializer, Serialize, ser::SerializeMap};
    use crate::stdlib::collections::HashMap;

    pub fn serialize_builtin_name_map_with_suffix<S, V>(
        values: &HashMap<BuiltinName, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let mut map_serializer = serializer.serialize_map(Some(values.len()))?;
        for (key, val) in values {
                map_serializer.serialize_entry(key.to_str_with_suffix(), val)?
            }
        map_serializer.end()
    }
}

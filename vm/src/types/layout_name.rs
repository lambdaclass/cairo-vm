#[cfg(all(feature = "arbitrary", feature = "std"))]
use arbitrary::{self, Arbitrary};
use core::fmt::{self, Display};
use serde::{Deserialize, Serialize};

// This enum is used to deserialize program layouts into &str and catch non-valid names
#[cfg_attr(all(feature = "arbitrary", feature = "std"), derive(Arbitrary))]
#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum LayoutName {
    plain,
    small,
    dex,
    recursive,
    starknet,
    starknet_with_keccak,
    recursive_large_output,
    all_solidity,
    all_cairo,
    dynamic,
}

impl LayoutName {
    pub fn to_str(&self) -> &'static str {
        match self {
            LayoutName::plain => "plain",
            LayoutName::small => "small",
            LayoutName::dex => "dex",
            LayoutName::recursive => "recursive",
            LayoutName::starknet => "starknet",
            LayoutName::starknet_with_keccak => "starknet_with_keccak",
            LayoutName::recursive_large_output => "recursive_large_output",
            LayoutName::all_solidity => "all_solidity",
            LayoutName::all_cairo => "all_cairo",
            LayoutName::dynamic => "all_cairo",
        }
    }
}

impl Display for LayoutName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutName::plain => "plain".fmt(f),
            LayoutName::small => "small".fmt(f),
            LayoutName::dex => "dex".fmt(f),
            LayoutName::recursive => "recursive".fmt(f),
            LayoutName::starknet => "starknet".fmt(f),
            LayoutName::starknet_with_keccak => "starknet_with_keccak".fmt(f),
            LayoutName::recursive_large_output => "recursive_large_output".fmt(f),
            LayoutName::all_solidity => "all_solidity".fmt(f),
            LayoutName::all_cairo => "all_cairo".fmt(f),
            LayoutName::dynamic => "all_cairo".fmt(f),
        }
    }
}

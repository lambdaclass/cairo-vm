use serde::{Deserialize, Serialize};

use crate::Felt252;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum PrivateInput {
    Value(PrivateInputValue),
    Pair(PrivateInputPair),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputValue {
    pub index: usize,
    pub value: Felt252,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputPair {
    pub index: usize,
    pub x: Felt252,
    pub y: Felt252,
}

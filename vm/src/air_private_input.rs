use serde::{Deserialize, Serialize};

use crate::Felt252;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum PrivateInput {
    Value(PrivateInputValue),
    Pair(PrivateInputPair),
    EcOp(PrivateInputEcOp),
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputEcOp {
    pub index: usize,
    pub p_x: Felt252,
    pub p_y: Felt252,
    pub m: Felt252,
    pub q_x: Felt252,
    pub q_y: Felt252,
}

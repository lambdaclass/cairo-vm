use serde::{Deserialize, Serialize};

use crate::Felt252;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum PrivateInput {
    Value(PrivateInputValue),
    Pair(PrivateInputPair),
    EcOp(PrivateInputEcOp),
    PoseidonState(PrivateInputPoseidonState),
    KeccakState(PrivateInputKeccakState),
    Signature(PrivateInputSignature),
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputPoseidonState {
    pub index: usize,
    pub input_s0: Felt252,
    pub input_s1: Felt252,
    pub input_s2: Felt252,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputKeccakState {
    pub index: usize,
    pub input_s0: Felt252,
    pub input_s1: Felt252,
    pub input_s2: Felt252,
    pub input_s3: Felt252,
    pub input_s4: Felt252,
    pub input_s5: Felt252,
    pub input_s6: Felt252,
    pub input_s7: Felt252,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateInputSignature {
    pub index: usize,
    pub pubkey: Felt252,
    pub msg: Felt252,
    pub signature_input: SignatureInput,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignatureInput {
    pub r: Felt252,
    pub w: Felt252,
}

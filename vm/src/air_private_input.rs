use crate::{
    stdlib::collections::HashMap,
    vm::runners::builtin_runner::{
        BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
        POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
    },
};
use serde::{Deserialize, Serialize};
use crate::stdlib::prelude::String;

use crate::Felt252;

// Serializable format, matches the file output of the python implementation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AirPrivateInputSerializable {
    trace_path: String,
    memory_path: String,
    pedersen: Vec<PrivateInput>,
    range_check: Vec<PrivateInput>,
    ecdsa: Vec<PrivateInput>,
    bitwise: Vec<PrivateInput>,
    ec_op: Vec<PrivateInput>,
    keccak: Vec<PrivateInput>,
    poseidon: Vec<PrivateInput>,
}

// Contains only builtin public inputs, useful for library users
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirPrivateInput(pub HashMap<&'static str, Vec<PrivateInput>>);

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

impl AirPrivateInput {
    pub fn to_serializable(
        &self,
        trace_path: String,
        memory_path: String,
    ) -> AirPrivateInputSerializable {
        AirPrivateInputSerializable {
            trace_path,
            memory_path,
            pedersen: self.0.get(HASH_BUILTIN_NAME).cloned().unwrap_or_default(),
            range_check: self
                .0
                .get(RANGE_CHECK_BUILTIN_NAME)
                .cloned()
                .unwrap_or_default(),
            ecdsa: self
                .0
                .get(SIGNATURE_BUILTIN_NAME)
                .cloned()
                .unwrap_or_default(),
            bitwise: self
                .0
                .get(BITWISE_BUILTIN_NAME)
                .cloned()
                .unwrap_or_default(),
            ec_op: self.0.get(EC_OP_BUILTIN_NAME).cloned().unwrap_or_default(),
            keccak: self.0.get(KECCAK_BUILTIN_NAME).cloned().unwrap_or_default(),
            poseidon: self
                .0
                .get(POSEIDON_BUILTIN_NAME)
                .cloned()
                .unwrap_or_default(),
        }
    }
}

impl AirPrivateInputSerializable {
    pub fn serialize_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self)
    }
}

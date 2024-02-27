use crate::{
    stdlib::{
        collections::HashMap,
        prelude::{String, Vec},
    },
    vm::runners::builtin_runner::{
        BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
        POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
    },
};
use serde::{Deserialize, Serialize};

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

impl From<AirPrivateInputSerializable> for AirPrivateInput {
    fn from(private_input: AirPrivateInputSerializable) -> Self {
        Self(HashMap::from([
            (HASH_BUILTIN_NAME, private_input.pedersen),
            (RANGE_CHECK_BUILTIN_NAME, private_input.range_check),
            (SIGNATURE_BUILTIN_NAME, private_input.ecdsa),
            (BITWISE_BUILTIN_NAME, private_input.bitwise),
            (EC_OP_BUILTIN_NAME, private_input.ec_op),
            (KECCAK_BUILTIN_NAME, private_input.keccak),
            (POSEIDON_BUILTIN_NAME, private_input.poseidon),
        ]))
    }
}

impl AirPrivateInputSerializable {
    pub fn serialize_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use {
        super::*,
        crate::air_private_input::{AirPrivateInput, AirPrivateInputSerializable},
        crate::vm::runners::builtin_runner::{
            BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
            POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME, SIGNATURE_BUILTIN_NAME,
        },
        assert_matches::assert_matches,
    };

    #[cfg(feature = "std")]
    #[test]
    fn test_from_serializable() {
        let serializable_private_input = AirPrivateInputSerializable {
            trace_path: "trace.bin".to_string(),
            memory_path: "memory.bin".to_string(),
            pedersen: vec![PrivateInput::Pair(PrivateInputPair {
                index: 0,
                x: Felt252::from(100),
                y: Felt252::from(200),
            })],
            range_check: vec![PrivateInput::Value(PrivateInputValue {
                index: 10000,
                value: Felt252::from(8000),
            })],
            ecdsa: vec![PrivateInput::Signature(PrivateInputSignature {
                index: 0,
                pubkey: Felt252::from(123),
                msg: Felt252::from(456),
                signature_input: SignatureInput {
                    r: Felt252::from(654),
                    w: Felt252::from(321),
                },
            })],
            bitwise: vec![PrivateInput::Pair(PrivateInputPair {
                index: 4,
                x: Felt252::from(7),
                y: Felt252::from(8),
            })],
            ec_op: vec![PrivateInput::EcOp(PrivateInputEcOp {
                index: 1,
                p_x: Felt252::from(10),
                p_y: Felt252::from(10),
                m: Felt252::from(100),
                q_x: Felt252::from(11),
                q_y: Felt252::from(14),
            })],
            keccak: vec![PrivateInput::KeccakState(PrivateInputKeccakState {
                index: 0,
                input_s0: Felt252::from(0),
                input_s1: Felt252::from(1),
                input_s2: Felt252::from(2),
                input_s3: Felt252::from(3),
                input_s4: Felt252::from(4),
                input_s5: Felt252::from(5),
                input_s6: Felt252::from(6),
                input_s7: Felt252::from(7),
            })],
            poseidon: vec![PrivateInput::PoseidonState(PrivateInputPoseidonState {
                index: 42,
                input_s0: Felt252::from(1),
                input_s1: Felt252::from(2),
                input_s2: Felt252::from(3),
            })],
        };

        let private_input = AirPrivateInput::from(serializable_private_input.clone());

        assert_matches!(private_input.0.get(HASH_BUILTIN_NAME), Some(data) if *data == serializable_private_input.pedersen);
        assert_matches!(private_input.0.get(RANGE_CHECK_BUILTIN_NAME), Some(data) if *data == serializable_private_input.range_check);
        assert_matches!(private_input.0.get(SIGNATURE_BUILTIN_NAME), Some(data) if *data == serializable_private_input.ecdsa);
        assert_matches!(private_input.0.get(BITWISE_BUILTIN_NAME), Some(data) if *data == serializable_private_input.bitwise);
        assert_matches!(private_input.0.get(EC_OP_BUILTIN_NAME), Some(data) if *data == serializable_private_input.ec_op);
        assert_matches!(private_input.0.get(KECCAK_BUILTIN_NAME), Some(data) if *data == serializable_private_input.keccak);
        assert_matches!(private_input.0.get(POSEIDON_BUILTIN_NAME), Some(data) if *data == serializable_private_input.poseidon);
    }
}

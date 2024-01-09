use crate::Felt252;

pub enum PrivateInput {
    Value(PrivateInputValue),
    Pair(PrivateInputPair),
}

pub struct PrivateInputValue {
    pub index: usize,
    pub value: Felt252,
}

pub struct PrivateInputPair {
    pub index: usize,
    pub x: Felt252,
    pub y: Felt252,
}

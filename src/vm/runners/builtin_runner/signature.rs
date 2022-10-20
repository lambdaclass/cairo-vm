use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::{memory_errors::MemoryError, runner_errors::RunnerError},
        vm_memory::{
            memory::{Memory, ValidationRule},
            memory_segments::MemorySegmentManager,
        },
    },
};

use super::BuiltinRunner;
use k256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use num_integer::Integer;
use std::{any::Any, collections::HashMap};

pub struct SignatureBuiltinRunner {
    _name: String,
    _included: bool,
    _ratio: usize,
    pub base: usize,
    cells_per_instance: usize,
    _n_input_cells: usize,
    _total_n_bits: u32,
    signatures: HashMap<Relocatable, Signature>,
}

impl SignatureBuiltinRunner {
    pub fn new(ratio: usize) -> Self {
        SignatureBuiltinRunner {
            base: 0,
            _name: "name".to_string(),
            _included: false,
            _ratio: ratio,
            cells_per_instance: 5,
            _n_input_cells: 2,
            _total_n_bits: 251,
            signatures: HashMap::new(),
        }
    }

    pub fn add_signature(&mut self, relocatable: Relocatable, signature: Signature) {
        self.signatures.entry(relocatable).or_insert(signature);
    }
}

impl BuiltinRunner for SignatureBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }

    fn add_validation_rule(&self, memory: &mut Memory) {
        let cells_per_instance = self.cells_per_instance;
        let signatures = self.signatures.clone();
        let rule: ValidationRule = ValidationRule(Box::new(
            move |memory: &Memory,
                  address: &MaybeRelocatable|
                  -> Result<Vec<MaybeRelocatable>, MemoryError> {
                let address = if let MaybeRelocatable::Int(_address) = address {
                    return Err(MemoryError::AddressNotRelocatable);
                } else if let MaybeRelocatable::RelocatableValue(address) = address {
                    address
                } else {
                    unreachable!()
                };

                let (pubkey_addr, msg_addr) = if let (0, Ok(Some(_element))) = (
                    address.offset.mod_floor(&cells_per_instance),
                    memory.get(&(address + 1_i32)),
                ) {
                    println!("primer caso");
                    let pubkey_addr = address.clone();
                    let msg_addr = address + 1_i32;
                    (pubkey_addr, Some(msg_addr))
                } else if address.offset > 0 {
                    if let (1, Ok(Some(_element))) = (
                        address.offset.mod_floor(&cells_per_instance),
                        memory.get(&address.sub(1).unwrap()),
                    ) {
                        println!("segundo caso");
                        let pubkey_addr = address.sub(1).unwrap().clone();
                        let msg_addr = address.clone();
                        (pubkey_addr, Some(msg_addr))
                    } else {
                        return Ok(Vec::new());
                    }
                } else {
                    println!("tercer caso");
                    return Ok(Vec::new());
                };

                let (_sign, msg) = memory
                    .get_integer(&msg_addr.unwrap())
                    .unwrap()
                    .to_bytes_be();
                let (_sign, pubkey) = memory
                    .get_integer(&pubkey_addr)
                    .unwrap()
                    .to_bytes_be();
                println!("{:?}", pubkey);
                println!("{:?}", msg);
                let signing_key = SigningKey::from_bytes(&pubkey).unwrap();
                let verify_key = VerifyingKey::from(&signing_key);
                let signature = signatures.get(&pubkey_addr).ok_or_else(|| MemoryError::AddressNotRelocatable)?;
                verify_key.verify(&msg, signature).unwrap();
                Ok(Vec::new())
            },
        ));
        memory.add_validation_rule(self.base, rule);
    }

    fn deduce_memory_cell(
        &mut self,
        _address: &Relocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_segments_for_range_check() {
        let mut builtin = SignatureBuiltinRunner::new(10);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.base, 0);
    }

    #[test]
    fn get_initial_stack_for_range_check_with_base() {
        let mut builtin = SignatureBuiltinRunner::new(10);
        builtin.base = 1;
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base())
        );
        assert_eq!(initial_stack.len(), 1);
    }
}

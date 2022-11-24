use crate::vm::errors::vm_errors::VirtualMachineError;

pub const PRIME_HIGH: u128 = (1 << 123) + (17 << 64);
pub const PRIME_LOW: u128 = 1;

pub type Field = FieldStruct<PRIME_HIGH, PRIME_LOW>;

pub struct FieldStruct<const HIGH: u128, const LOW: u128> {}

impl<const HIGH: u128, const LOW: u128> FieldStruct<HIGH, LOW> {
    pub fn new(input_prime: &str) -> Result<Self, VirtualMachineError> {
        let assembled_prime = format!("{:x}{:032x}", PRIME_HIGH, PRIME_LOW);
        if assembled_prime != input_prime {
            Err(VirtualMachineError::PrimeDiffers(
                input_prime.to_string(),
                PRIME_HIGH,
                PRIME_HIGH,
            ))
        } else {
            Ok(FieldStruct {})
        }
    }
}

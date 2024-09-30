use core::{
    array,
    ops::{Deref, Shl},
};

use ark_ff::{One, Zero};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::{ExtendedGcd, Integer};
use num_traits::Signed;
use starknet_types_core::felt::Felt;

use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

// A gate is defined by 3 offsets, the first two are the inputs and the third is the output.
const OFFSETS_PER_GATE: usize = 3;
// Represents the number of limbs use to represent a single value in a circuit
const LIMBS_COUNT: usize = 4;
// Representes the size of a MulMod and AddMod instance
const MOD_BUILTIN_INSTACE_SIZE: usize = 7;

struct CircuitInstance<'a> {
    vm: &'a mut VirtualMachine,
    values_ptr: Relocatable,
    add_mod_offsets: Relocatable,
    mul_mod_offsets: Relocatable,
    modulus: BigUint,
}

impl CircuitInstance<'_> {
    fn read_add_mod_value(&mut self, offset: usize) -> Option<BigUint> {
        self.read_circuit_value((self.add_mod_offsets + offset).unwrap())
    }

    fn read_mul_mod_value(&mut self, offset: usize) -> Option<BigUint> {
        self.read_circuit_value((self.mul_mod_offsets + offset).unwrap())
    }

    fn read_circuit_value(&mut self, offset: Relocatable) -> Option<BigUint> {
        let value_ptr = self.get_value_ptr(offset);
        read_circuit_value(self.vm, value_ptr)
    }

    fn write_add_mod_value(&mut self, offset: usize, value: BigUint) {
        self.write_circuit_value((self.add_mod_offsets + offset).unwrap(), value);
    }

    fn write_mul_mod_value(&mut self, offset: usize, value: BigUint) {
        self.write_circuit_value((self.mul_mod_offsets + offset).unwrap(), value);
    }

    fn write_circuit_value(&mut self, offset: Relocatable, value: BigUint) {
        let value_ptr = self.get_value_ptr(offset);
        write_circuit_value(self.vm, value_ptr, value);
    }

    fn get_value_ptr(&self, address: Relocatable) -> Relocatable {
        (self.values_ptr + self.vm.get_integer(address).unwrap().as_ref()).unwrap()
    }

    /// Fills an `add_mod` gate
    ///
    /// Returns `true` if all the inputs of the gate are filled up and so the operation can be performed,
    /// `false` otherwise.
    fn fill_add_gate(&mut self, index: usize) -> bool {
        let lhs = self.read_add_mod_value(index);
        let rhs = self.read_add_mod_value(index + 1);

        match (lhs, rhs) {
            (Some(l), Some(r)) => {
                let res = (l + r) % &self.modulus;
                self.write_add_mod_value(index + 2, res);
                true
            }
            // sub gate: lhs + rhs = res => lhs = res - rhs
            (None, Some(r)) => {
                let Some(res) = self.read_add_mod_value(index + 2) else {
                    return false;
                };
                let value = (res + &self.modulus - r) % &self.modulus;
                self.write_add_mod_value(index, value);
                true
            }
            _ => false,
        }
    }

    /// Fills the a `mul_mod` gate
    ///
    /// Returns `true` if all the inputs of the gates are filled up and so the operation can be performed,
    /// false if it is an inverse opeartion with a non invertible input.
    ///
    /// This operation implies that all the gate's inputs are filled up,
    /// and will panic if that is not the case.
    fn fill_mul_gate(&mut self, index: usize) -> bool {
        let lhs = self.read_mul_mod_value(index);
        let rhs = self.read_mul_mod_value(index + 1);

        match (lhs, rhs) {
            (Some(l), Some(r)) => {
                let res = (l * r) % &self.modulus;
                self.write_mul_mod_value(index + 2, res);
                true
            }
            // inverse gate: lhs * rhs = 1 => lhs = 1 / rhs
            (None, Some(r)) => {
                let (success, res) = invert_or_nullify(r, &self.modulus);
                self.write_mul_mod_value(index, res);
                success
            }
            _ => unreachable!("Unexpected None value while filling mul_mod gate"),
        }
    }
}

/// Reads a circuit value from memory
fn read_circuit_value(vm: &mut VirtualMachine, add: Relocatable) -> Option<BigUint> {
    let mut res = BigUint::zero();

    for l in (0..LIMBS_COUNT).rev() {
        let add_l = (add + l).unwrap();
        match vm.get_maybe(&add_l) {
            Some(MaybeRelocatable::Int(limb)) => res = (res << 96) + limb.to_biguint(),
            _ => return None,
        }
    }

    Some(res)
}

// Writes a circuit value in memory
fn write_circuit_value(vm: &mut VirtualMachine, add: Relocatable, mut value: BigUint) {
    for l in 0..LIMBS_COUNT {
        // get the nth limb from a circuit value
        let (new_value, rem) = value.div_rem(&BigUint::one().shl(96));
        vm.insert_value((add + l).unwrap(), Felt::from(rem))
            .unwrap();
        value = new_value;
    }
}

fn invert_or_nullify(value: BigUint, modulus: &BigUint) -> (bool, BigUint) {
    let ExtendedGcd::<_> { gcd, x, y: _ } =
            value.to_bigint().unwrap().extended_gcd(&modulus.to_bigint().unwrap());

        let gcd = gcd.to_biguint().unwrap();
        if gcd.is_one() {
            return (true, positive_modulus(&x, modulus));
        }
        let nullifier = modulus / gcd;
        // Note that gcd divides the value, so value * nullifier = value * (modulus / gcd) =
        // (value // gcd) * modulus = 0 (mod modulus)
        (false, nullifier)
}

fn positive_modulus(value: &BigInt, modulus: &BigUint) -> BigUint {
    let value_magnitud = value.magnitude().mod_floor(modulus);
    if value.is_negative() { modulus - value_magnitud } else { value_magnitud }
}

/// Fills the values for a circuit
///
/// Returns the first mul gate index that failed to fill its values or
/// `n_mul_mods` if all gates were filled successfully
fn fill_values(
    vm: &mut VirtualMachine,
    values_ptr: Relocatable,
    add_mod_offsets: Relocatable,
    n_add_mods: usize,
    mul_mod_offsets: Relocatable,
    n_mul_mods: usize,
    modulus_ptr: Relocatable,
) -> usize {
    let modulus = read_circuit_value(vm, modulus_ptr).unwrap();
    let mut circuit = CircuitInstance {
        vm,
        values_ptr,
        add_mod_offsets,
        mul_mod_offsets,
        modulus,
    };

    let mut addmod_idx = 0;
    let mut mulmod_idx = 0;

    // A circuit evaluation can only fail through a mulmod operation
    let mut first_failure_idx = n_mul_mods;

    loop {
        while addmod_idx < n_add_mods {
            if !circuit.fill_add_gate(3 * addmod_idx) {
                break;
            }
            addmod_idx += 1;
        }

        if mulmod_idx == n_mul_mods {
            break;
        }

        if !circuit.fill_mul_gate(3 * mulmod_idx) && first_failure_idx == n_mul_mods {
            first_failure_idx = mulmod_idx;
        }
        mulmod_idx += 1;
    }

    first_failure_idx
}

fn fill_instances(
    vm: &mut VirtualMachine,
    built_ptr: Relocatable,
    n_instances: usize,
    modulus: [Felt; LIMBS_COUNT],
    values_ptr: Relocatable,
    mut offsets_ptr: Relocatable,
) -> Result<(), HintError> {
    for i in 0..n_instances {
        let instance_ptr = (built_ptr + i * MOD_BUILTIN_INSTACE_SIZE).unwrap();

        for (idx, value) in modulus.iter().enumerate() {
            vm.insert_value((instance_ptr + idx)?, *value)?;
        }

        vm.insert_value((instance_ptr + 4)?, values_ptr)?;
        vm.insert_value((instance_ptr + 5)?, offsets_ptr)?;
        offsets_ptr += OFFSETS_PER_GATE;
        vm.insert_value((instance_ptr + 6)?, n_instances - i)?;
    }
    Ok(())
}

/// Evaluates a circuit and fills the builtin instances and the values buffer.
///
/// Returns the first mul gate index that failed to fill its values
/// or `n_mul_mods` if all gates were filled successfully.
pub fn eval_circuit(
    vm: &mut VirtualMachine,
    n_add_mods: usize,
    add_mod_builtin_address: Relocatable,
    n_mul_mods: usize,
    mul_mod_builtin_address: Relocatable,
) -> Result<(), HintError> {
    let modulus_ptr = mul_mod_builtin_address;
    // The offset of the values pointer inside the mul_mod_builtin
    let values_offset = 4;
    // The offset of the offsets pointer inside the mul_mod_builtin
    let offsets_offset = 5;

    let values_ptr = vm.get_relocatable((mul_mod_builtin_address + values_offset)?)?;
    let mul_mod_offsets = vm.get_relocatable((mul_mod_builtin_address + offsets_offset)?)?;
    let add_mod_offsets = if n_add_mods == 0 {
        mul_mod_offsets
    } else {
        vm.get_relocatable((add_mod_builtin_address + offsets_offset)?)?
    };

    let n_computed_gates = fill_values(
        vm,
        values_ptr,
        add_mod_offsets,
        n_add_mods,
        mul_mod_offsets,
        n_mul_mods,
        modulus_ptr,
    );

    let modulus: [Felt; 4] =
        array::from_fn(|l| *vm.get_integer((modulus_ptr + l).unwrap()).unwrap().deref());

    fill_instances(
        vm,
        add_mod_builtin_address,
        n_add_mods,
        modulus,
        values_ptr,
        add_mod_offsets,
    )?;
    fill_instances(
        vm,
        mul_mod_builtin_address,
        n_computed_gates,
        modulus,
        values_ptr,
        mul_mod_offsets,
    )?;

    Ok(())
}

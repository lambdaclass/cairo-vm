use ark_ff::Zero;
use num_bigint::BigUint;

use crate::{types::relocatable::{MaybeRelocatable, Relocatable}, vm::vm_core::VirtualMachine};

// Represents the number of limbs use to represent a single value in a circuit
const LIMBS_COUNT: usize = 4;

struct CircuitInstance<'a> {
    vm: &'a mut VirtualMachine,
    values_ptr: Relocatable,
    add_mod_offsets: Relocatable,
    mul_mod_offsets: Relocatable,
    modulus: BigUint,
}

impl CircuitInstance<'_> {
    fn fill_add_gate(&mut self, index: usize) -> bool {todo!()}
    fn fill_mul_gate(&mut self, index: usize) -> bool {todo!()}
}

fn read_circuit_value(vm: &mut VirtualMachine, add: Relocatable) -> Option<BigUint> {
    let mut res = BigUint::zero();

    for l in (0..LIMBS_COUNT).rev() {
        let add_l = (add + l).unwrap();
        match vm.get_maybe(&add_l) {
            Some(MaybeRelocatable::Int(limb)) => res = (res << 96) + limb.to_biguint(),
            _ => return None
        }
    }

    Some(res)
}

pub fn fill_values(
    vm: &mut VirtualMachine,
    values_ptr: Relocatable,
    add_mod_offsets: Relocatable,
    n_add_mods: usize,
    mul_mod_offsets: Relocatable,
    n_mul_mods: usize,
    modulus_ptr: Relocatable,
) -> usize {
    let modulus = read_circuit_value(vm, modulus_ptr).unwrap();
    let circuit = CircuitInstance {vm, values_ptr, add_mod_offsets, mul_mod_offsets, modulus};

    let mut addmod_idx = 0;
    let mut mulmod_idx = 0;

    // A circuit evaluation can only fail through a mulmod operation
    let mut first_failure_idx = n_mul_mods;

    loop {
        while addmod_idx < n_add_mods {
            if !circuit.fill_add_gate() {
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
    0
}

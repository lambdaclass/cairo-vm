use core::poseidon::PoseidonTrait;
use core::hash::{HashStateTrait, HashStateExTrait};
use core::testing::get_available_gas;

fn main() -> Array<felt252> {
    let a: u128 = get_available_gas();
    let b = PoseidonTrait::new().update_with(a).finalize();
    let mut ser_output: Array<felt252> = ArrayTrait::new();

    b.serialize(ref ser_output);

    ser_output
}

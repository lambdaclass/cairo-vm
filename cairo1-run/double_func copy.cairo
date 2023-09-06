use core::felt252;

fn main() {
    let x = 10;
    let y = 10;
    let z = add_and_double(x,y);
    return;
}

fn add_and_double(x: felt252, y: felt252) -> felt252 {
    return double(x + y);
}

fn double(x: felt252) -> felt252 {
    return x*2;
}

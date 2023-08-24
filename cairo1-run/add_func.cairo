use core::felt252;

fn main() {
    let x = 10;
    let y = 10;
    let z = add(x,y);
    let u = add(z,x);

    return;
}

fn add(x: felt252, y: felt252) -> felt252 {
    return x + y;
}

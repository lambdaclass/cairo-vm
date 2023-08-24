use core::felt252;

fn main() {
    let n = 2;
    let result = factorial(n);
    return;
}

fn factorial(n: felt252) -> felt252 {

    if n == 1 {
        return 1;
    } else {
        return n * factorial(n - 1);
    }
}

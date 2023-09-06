use core::felt252;

fn main() {
    let mut i: usize = 0;
    loop {
        if i > 10 {
            break;
        }
        if i == 5 {
            i += 1;
            continue;
        }
        i += 1;
    }
}

fn double(x: felt252) -> felt252 {
    if x == 5 {
        return 3;
    } else {
        return 5;
    }
}

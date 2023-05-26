#[contract]
mod Factorial {

    #[external]
    fn multiply_rec(n: felt252) -> felt252 {
        if (n == 0) {
            return 1;
        }
        n * multiply_rec(n - 1)
    }
}

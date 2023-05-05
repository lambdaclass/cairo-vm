#[contract]
mod LinearSplit {
    use integer::u8_try_from_felt252;

     #[external]
    fn cast(a: felt252) -> Option<u8> {
        u8_try_from_felt252(a)
    }   
}
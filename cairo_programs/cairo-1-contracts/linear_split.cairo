#[contract]
mod LinearSplit {

     #[external]
    fn cast(a: felt252) -> u8 {
        u8_try_from_felt252(a).unwrap()
    }   
}
#[contract]
mod DebugPrint {
use debug::PrintTrait;

    #[external]
    fn print_felt252(message: felt252) {
        let val = 1;
        print(val);
    }
}
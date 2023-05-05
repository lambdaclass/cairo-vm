#[contract]
mod Felt252Dict {

use dict::{felt252_dict_entry_finalize, Felt252DictTrait};
    /// An external method that requires the `segment_arena` builtin.
    #[external]
    fn segment_arena_builtin() -> bool {
        let x = felt252_dict_new::<felt252>();
        x.squash();
        return true;
    }
}
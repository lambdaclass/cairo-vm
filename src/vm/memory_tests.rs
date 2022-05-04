use crate::vm::memory::Memory;
use std::collections::HashMap;
use crate::vm::relocatable::MaybeRelocatable;
use num_bigint::BigInt;

#[cfg(test)]
pub mod memory_tests {
    #[test]
    pub fn get_test () {
        let key = MaybeRelocatable::Int(BigInt::from(2))
        let val = MaybeRelocatable::Int(BigInt::from(5))
        let mem:Memory {
            HashMap::from([(key, val)])
        };
        assert_eq!(mem.get(&key), MaybeRelocatable::Int(BigInt::from(5)));
    }
}

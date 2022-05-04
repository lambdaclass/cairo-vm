use crate::vm::relocatable::MaybeRelocatable;
use std::collections::HashMap;

struct Memory {
    data: HashMap<MaybeRelocatable, MaybeRelocatable>,
}

impl Memory {
    fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        return self.data.get(&addr);
    }
}

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


use crate::vm::relocatable::MaybeRelocatable;
use std::collections::HashMap;

<<<<<<< HEAD
pub struct Memory {
=======
struct Memory {
>>>>>>> ca9186fcfae3890011d50fd238eda44c70ef70b9
    data: HashMap<MaybeRelocatable, MaybeRelocatable>,
}

impl Memory {
<<<<<<< HEAD
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        return self.data.get(&addr);
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    #[test]
    fn get_test () {
        let key = MaybeRelocatable::Int(BigInt::from_i32(2).unwrap());
        let val = MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let key_clone = key.clone();
        let val_clone = val.clone();
        let mem = Memory {
            data: HashMap::from([(key, val)])
        };
        assert_eq!(mem.get(&key_clone), Some(&val_clone));
    }
}

=======
    fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        return self.data.get(addr);
    }
}
>>>>>>> ca9186fcfae3890011d50fd238eda44c70ef70b9

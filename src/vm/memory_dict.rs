mod relocatable;

use num_bigint::BigUint;
use relocatable::RelocatableValue
struct MemoryDict {
    data: HashMap,
    frozen: bool,
    relocation_rules: HashMap<BigUint, RelocatableValue>
}

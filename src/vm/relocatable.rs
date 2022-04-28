use num_bigint::BigUint;

struct RelocatableValue {
    segment_index: BigUint,
    offset: BigUint
}

enum MaybeRelocatable {
    RelocatableValue(RelocatableValue),
    Int(BigUint)
}

struct NullableVec<T> {
    items: SquashedFelt252Dict<Nullable<Box<T>>>,
    len: usize,
}

fn main() -> NullableVec<u32> {
    let mut d: Felt252Dict<Nullable<Box<u32>>> = Default::default();

    // Populate the dictionary
    d.insert(0, nullable_from_box(BoxTrait::new(BoxTrait::new(10))));
    d.insert(1, nullable_from_box(BoxTrait::new(BoxTrait::new(20))));
    d.insert(2, nullable_from_box(BoxTrait::new(BoxTrait::new(30))));

    // Return NullableVec
    NullableVec {
        items: d.squash(),
        len: 3,
    }
}

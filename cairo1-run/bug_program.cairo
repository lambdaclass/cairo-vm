use core::nullable::{nullable_from_box, match_nullable, FromNullableResult};

fn main() -> Felt252Dict<Nullable<Span<felt252>>> {
    // Create the dictionary
    let mut d: Felt252Dict<Nullable<Span<felt252>>> = Default::default();

    // Create the array to insert
    let a = array![8, 9, 10, 11];
    let b = array![1, 2, 3];
    // Insert it as a `Span`
    d.insert(66675, nullable_from_box(BoxTrait::new(a.span())));
 d.insert(66676, nullable_from_box(BoxTrait::new(b.span())));
    d


    // Get value back
 //   let val = d.get(0);

    // Search the value and assert it is not null
 //   let span = match match_nullable(val) {
  //      FromNullableResult::Null => panic!("No value found"),
  //      FromNullableResult::NotNull(val) => val.unbox(),
   // };

    // Verify we are having the right values
    //assert!(*span.at(0) == 8, "Expecting 8");
}

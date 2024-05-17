use core::nullable::{nullable_from_box, match_nullable, FromNullableResult};

fn main() -> Array<felt252> {
   let a = array![8, 9, 10, 11];
   let res = nullable_from_box(BoxTrait::new(a.span()));

   let mut output: Array<felt252> = ArrayTrait::new();
   res.serialize(ref output);
   output
}

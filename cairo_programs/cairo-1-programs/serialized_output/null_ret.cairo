fn main() -> Array<felt252> {
   let res = null();
   let mut output: Array<felt252> = ArrayTrait::new();
   res.serialize(ref output);
   output 
}

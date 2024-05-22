use array::ArrayTrait;

<<<<<<< HEAD
fn main(input: Array<felt252>) -> Array<felt252> {
    let mut input = input.span();
    let (array_a, array_b): (Array<u32>, Array<u32>) = Serde::deserialize(ref input).unwrap();

=======
fn main(array_a: Array<u32>, array_b: Array<u32>) -> Array<felt252> {
>>>>>>> f4a22140018f62309ade09ecd517b40e915031b1
    let res = array_a.len() + array_b.len();
    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

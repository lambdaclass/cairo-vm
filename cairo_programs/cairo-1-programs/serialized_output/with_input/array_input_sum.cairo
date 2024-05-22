use array::ArrayTrait;

<<<<<<< HEAD
fn main(input: Array<felt252>) -> Array<felt252> {
    let mut input = input.span();
    let (index_a, array_a, index_b, array_b): (u32, Array<u32>, u32, Array<u32>) = Serde::deserialize(ref input).unwrap();

=======
fn main(index_a: u32, array_a: Array<u32>, index_b: u32, array_b: Array<u32>) -> Array<felt252> {
>>>>>>> f4a22140018f62309ade09ecd517b40e915031b1
    let res = *array_a.at(index_a) + *array_b.at(index_b);

    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

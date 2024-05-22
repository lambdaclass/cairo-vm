use array::ArrayTrait;

fn main(array_a: Array<u32>, array_b: Array<u32>) -> Array<felt252> {
    let res = array_a.len() + array_b.len();
    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

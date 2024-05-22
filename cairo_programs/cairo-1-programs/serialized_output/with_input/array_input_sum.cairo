use array::ArrayTrait;

fn main(index_a: u32, array_a: Array<u32>, index_b: u32, array_b: Array<u32>) -> Array<felt252> {
    let res = *array_a.at(index_a) + *array_b.at(index_b);

    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

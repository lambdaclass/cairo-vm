#[derive(Copy, Drop)]
struct Tensor {
    shape: Span<u32>,
    data: Span<u32>
}

fn main(tensor: Tensor) -> Array<felt252> {
    let res = *tensor.data.at(0);

    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

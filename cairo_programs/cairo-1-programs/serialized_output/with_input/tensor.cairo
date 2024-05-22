<<<<<<< HEAD
#[derive(Copy, Drop, Serde)]
=======
#[derive(Copy, Drop)]
>>>>>>> f4a22140018f62309ade09ecd517b40e915031b1
struct Tensor {
    shape: Span<u32>,
    data: Span<u32>
}
<<<<<<< HEAD
fn main(input: Array<felt252>) -> Array<felt252> {
    let mut input = input.span();
    let tensor : Tensor = Serde::deserialize(ref input).unwrap();
=======

fn main(tensor: Tensor) -> Array<felt252> {
>>>>>>> f4a22140018f62309ade09ecd517b40e915031b1
    let res = *tensor.data.at(0);

    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

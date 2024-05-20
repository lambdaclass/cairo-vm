fn main(argc: u32) -> Array<felt252> {
    let res = if argc == 0 {
        1_u8
    } else {
        0_u8
    };

    let mut output: Array<felt252> = ArrayTrait::new();
    res.serialize(ref output);
    output
}

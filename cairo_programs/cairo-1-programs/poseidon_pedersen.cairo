use core::felt252;
use core::poseidon::poseidon_hash_span;
use array::ArrayTrait;
use array::SpanTrait;
use core::pedersen::pedersen;

fn main() -> felt252 {
    let mut data: Array<felt252> = ArrayTrait::new();
    data.append(1);
    data.append(2);
    data.append(3);
    data.append(4);
    
    let res = poseidon_hash_span(data.span());
    pedersen(res, 0)
}

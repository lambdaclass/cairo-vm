use core::felt252;
use array::ArrayTrait;
use array::SpanTrait;

fn main() -> felt252 {
    let mut data: Array<felt252> = ArrayTrait::new();
    data.append(1);
    data.append(2);
    data.append(3);
    data.append(4);
    
    poseidon_hash_span(data.span())
}

// Modified version of poseidon_hash_span that doesn't require builtin gas costs
pub fn poseidon_hash_span(mut span: Span<felt252>) -> felt252 {
    _poseidon_hash_span_inner((0, 0, 0), ref span)
}

/// Helper function for poseidon_hash_span.
fn _poseidon_hash_span_inner(
    state: (felt252, felt252, felt252),
    ref span: Span<felt252>
) -> felt252 {
    let (s0, s1, s2) = state;
    let x = *match span.pop_front() {
        Option::Some(x) => x,
        Option::None => { return HashState { s0, s1, s2, odd: false }.finalize(); },
    };
    let y = *match span.pop_front() {
        Option::Some(y) => y,
        Option::None => { return HashState { s0: s0 + x, s1, s2, odd: true }.finalize(); },
    };
    let next_state = hades_permutation(s0 + x, s1 + y, s2);
    _poseidon_hash_span_inner(next_state, ref span)
}

%builtins output

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.keccak import unsafe_keccak

func main{output_ptr: felt*}():
    alloc_locals

    let (data : felt*) = alloc()

    assert data[0] = 0
    assert data[1] = 0
    assert data[2] = 0

    let (low : felt, high : felt) = unsafe_keccak(data, 3)

    serialize_word(low)
    serialize_word(high)

    return ()
end
    

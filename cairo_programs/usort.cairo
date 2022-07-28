%builtins range_check
from starkware.cairo.common.usort import usort
from starkware.cairo.common.alloc import alloc

func main{range_check_ptr}() -> ():
    alloc_locals
    let (expected_array: felt*) = alloc()
    assert expected_array[0] = 0
    assert expected_array[1] = 1
    assert expected_array[2] = 2

    let (input_array: felt*) = alloc()
    assert input_array[0] = 2
    assert input_array[1] = 1
    assert input_array[2] = 0

    let (output_len, output, multiplicities) = usort(input_len=3, input=input_array)

    assert output_len = 3
    assert output[0] = expected_array[0]
    assert output[1] = expected_array[1]
    assert output[2] = expected_array[2]
    assert multiplicities[0] = 1
    assert multiplicities[1] = 1
    assert multiplicities[2] = 1
    return()
end

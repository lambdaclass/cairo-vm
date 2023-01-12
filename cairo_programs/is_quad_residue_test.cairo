from starkware.cairo.common.math import is_quad_residue
from starkware.cairo.common.alloc import alloc

func fill_array(array_start: felt*, iter: felt) -> () {
    if (iter == 32) {
        return ();
    }
    assert array_start[iter] = iter;
    return fill_array(array_start, iter + 1);
}

func check_quad_res(inputs: felt*, expected: felt*, iter: felt) {
    if (iter == 32) {
        return ();
    }

    assert is_quad_residue(inputs[iter]) = expected[iter];
    return check_quad_res(inputs, expected, iter + 1);
}

func main() {
    alloc_locals;
    let (inputs: felt*) = alloc();
    fill_array(inputs, 0);

    let (expected: felt*) = alloc();
    assert expected[0] = 1;
    assert expected[1] = 1;
    assert expected[2] = 1;
    assert expected[3] = 0;
    assert expected[4] = 1;
    assert expected[5] = 1;
    assert expected[6] = 0;
    assert expected[7] = 1;
    assert expected[8] = 1;
    assert expected[9] = 1;
    assert expected[10] = 1;
    assert expected[11] = 1;
    assert expected[12] = 0;
    assert expected[13] = 1;
    assert expected[14] = 1;
    assert expected[15] = 0;
    assert expected[16] = 1;
    assert expected[17] = 1;
    assert expected[18] = 1;
    assert expected[19] = 0;
    assert expected[20] = 1;
    assert expected[21] = 0;
    assert expected[22] = 1;
    assert expected[23] = 0;
    assert expected[24] = 0;
    assert expected[25] = 1;
    assert expected[26] = 1;
    assert expected[27] = 0;
    assert expected[28] = 1;
    assert expected[29] = 0;
    assert expected[30] = 0;
    assert expected[31] = 1;

    check_quad_res(inputs, expected, 0);

    return();
}

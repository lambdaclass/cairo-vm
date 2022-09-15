%builtins range_check

func assert_le_felt_hint{range_check_ptr}(a, b) {
    const PRIME_OVER_3_HIGH = 0x2aaaaaaaaaaaab05555555555555556;
    const PRIME_OVER_2_HIGH = 0x4000000000000088000000000000001;
    %{
        import itertools

        from starkware.cairo.common.math_utils import assert_integer
        assert_integer(ids.a)
        assert_integer(ids.b)
        a = ids.a % PRIME
        b = ids.b % PRIME
        assert a <= b, f'a = {a} is not less than or equal to b = {b}.'

        # Find an arc less than PRIME / 3, and another less than PRIME / 2.
        lengths_and_indices = [(a, 0), (b - a, 1), (PRIME - 1 - b, 2)]
        lengths_and_indices.sort()
        assert lengths_and_indices[0][0] <= PRIME // 3 and lengths_and_indices[1][0] <= PRIME // 2
        excluded = lengths_and_indices[2][1]

        memory[ids.range_check_ptr + 1], memory[ids.range_check_ptr + 0] = (
            divmod(lengths_and_indices[0][0], ids.PRIME_OVER_3_HIGH))
        memory[ids.range_check_ptr + 3], memory[ids.range_check_ptr + 2] = (
            divmod(lengths_and_indices[1][0], ids.PRIME_OVER_2_HIGH))
    %}

    tempvar arc_short = [range_check_ptr] + [range_check_ptr + 1] * PRIME_OVER_3_HIGH;
    tempvar arc_long = [range_check_ptr + 2] + [range_check_ptr + 3] * PRIME_OVER_2_HIGH;
    let range_check_ptr = range_check_ptr + 4;

    let arc_sum = arc_short + arc_long;
    let arc_prod = arc_short * arc_long;

    %{ memory[ap] = 1 if excluded != 0 else 0 %}
    jmp skip_exclude_a if [ap] != 0, ap++;
    assert arc_sum = (-1) - a;
    assert arc_prod = (a - b) * (1 + b);
    return ();

    skip_exclude_a:
    %{ memory[ap] = 1 if excluded != 1 else 0 %}
    jmp skip_exclude_b_minus_a if [ap] != 0, ap++;
    tempvar m1mb = (-1) - b;
    assert arc_sum = a + m1mb;
    assert arc_prod = a * m1mb;
    return ();

    skip_exclude_b_minus_a:
    %{ assert excluded == 2 %}
    assert arc_sum = b;
    assert arc_prod = a * (b - a);
    ap += 2;
    return ();
}


func main{range_check_ptr: felt}() {
    assert_le_felt_hint(1, 2);
    return ();
}

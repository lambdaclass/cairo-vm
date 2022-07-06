# Implementation of math.cairo functions
A resume of the math.cairo functions, hints used and function depedencies 

https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/math.cairo#L39


## func assert_not_zero: 
* Status: WIP, https://github.com/lambdaclass/cleopatra_cairo/pull/225
* Assignee: Peter
* Hints:

```
    %{
        from starkware.cairo.common.math_utils import assert_integer
        assert_integer(ids.value)
        assert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'
    %}
```



* Depends on functions: None


## func assert_not_equal(a, b):
* Status: WIP,  https://github.com/lambdaclass/cleopatra_cairo/pull/229
* Assignee: Fede
* Hints:
```
    %{
        from starkware.cairo.lang.vm.relocatable import RelocatableValue
        both_ints = isinstance(ids.a, int) and isinstance(ids.b, int)
        both_relocatable = (
            isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and
            ids.a.segment_index == ids.b.segment_index)
        assert both_ints or both_relocatable, \
            f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'
        assert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'
    %}
```

* Depends on functions: None


## func assert_nn{range_check_ptr}(a):
* Status: WIP, https://github.com/lambdaclass/cleopatra_cairo/pull/243
* Assignee: Peter 
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import assert_integer
        assert_integer(ids.a)
        assert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'
    %}
```

* Depends on functions: None

## func assert_le{range_check_ptr}(a, b):
* Status:
* Assignee:
* Hints: None
* Depends on functions: 
    * `assert_nn`


## func assert_lt{range_check_ptr}(a, b):
* Status:
* Assignee: 
* Hints: None
* Depends on functions:
    * `assert_le`

## func assert_nn_le{range_check_ptr}(a, b):
* Status:
* Assignee: 
* Hints: None
* Depends on functions:
    * `assert_nn`
    * `assert_le`

## func assert_in_range{range_check_ptr}(value, lower, upper):
* Status:
* Assignee: 
* Hints: None
* Depends on functions:
    * `assert_le`


## func assert_250_bit{range_check_ptr}(value):
* Status: WIP, https://github.com/lambdaclass/cleopatra_cairo/pull/231
* Assignee: Fede
* Hints:

```
    %{
        from starkware.cairo.common.math_utils import as_int

        # Correctness check.
        value = as_int(ids.value, PRIME) % PRIME
        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'

        # Calculation for the assertion.
        ids.high, ids.low = divmod(ids.value, ids.SHIFT)
    %}
```

* Depends on functions: None


## func split_felt{range_check_ptr}(value) -> (high : felt, low : felt):
* Status: WIP
* Assignee: Peter
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import assert_integer
        assert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128
        assert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW
        assert_integer(ids.value)
        ids.low = ids.value & ((1 << 128) - 1)
        ids.high = ids.value >> 128
    %}
```

* Depends on functions:
    * `assert_le`


## func assert_le_felt{range_check_ptr}(a, b):
* Status: Merged (Hint tested alone)
* Assignee: Fede
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import assert_integer
        assert_integer(ids.a)
        assert_integer(ids.b)
        a = ids.a % PRIME
        b = ids.b % PRIME
        assert a <= b, f'a = {a} is not less than or equal to b = {b}.'

        ids.small_inputs = int(
            a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)
    %}
```

* Depends on functions:
    * `assert_nn_le`
    * `split_felt`
    * `assert_le`


## func assert_lt_felt{range_check_ptr}(a, b):
* Status:
* Assignee: 
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import assert_integer
        assert_integer(ids.a)
        assert_integer(ids.b)
        assert (ids.a % PRIME) < (ids.b % PRIME), \
            f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'
    %}
```

* Depends on functions:
    * `split_felt`
    * `assert_lt`


## func abs_value{range_check_ptr}(value):
* Status: WIP
* Assignee: Fede
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import is_positive
        ids.is_positive = 1 if is_positive(
            value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0
    %}
```

* Depends on functions: None


## func sign{range_check_ptr}(value):
* Status:
* Assignee: 
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import is_positive
        ids.is_positive = 1 if is_positive(
            value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0
    %}
```
* Depends on functions: None


## func unsigned_div_rem{range_check_ptr}(value, div):
* Status:
* Assignee: 
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import assert_integer
        assert_integer(ids.div)
        assert 0 < ids.div <= PRIME // range_check_builtin.bound, \
            f'div={hex(ids.div)} is out of the valid range.'
        ids.q, ids.r = divmod(ids.value, ids.div)
    %}
```

* Depends on functions:
    * `assert_le`

## func signed_div_rem{range_check_ptr}(value, div, bound):
* Status:
* Assignee: 
* Hints:
```
    %{
        from starkware.cairo.common.math_utils import as_int, assert_integer

        assert_integer(ids.div)
        assert 0 < ids.div <= PRIME // range_check_builtin.bound, \
            f'div={hex(ids.div)} is out of the valid range.'

        assert_integer(ids.bound)
        assert ids.bound <= range_check_builtin.bound // 2, \
            f'bound={hex(ids.bound)} is out of the valid range.'

        int_value = as_int(ids.value, PRIME)
        q, ids.r = divmod(int_value, ids.div)

        assert -ids.bound <= q < ids.bound, \
            f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'

        ids.biased_q = q + ids.bound
    %}
```

* Depends on functions:
    * `assert_le`



## func split_int{range_check_ptr}(value, n, base, bound, output : felt*):
* Status:
* Assignee: 
* Hints:
```
    %{ assert ids.value == 0, 'split_int(): value is out of range.' %}
```

```
    %{
        memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
        assert res < ids.bound, f'split_int(): Limb {res} is out of range.'
    %}
```

* Depends on functions:
    * `assert_nn_le`


## func sqrt{range_check_ptr}(value):
* Status:
* Assignee: 
* Hints:
```
    %{
        from starkware.python.math_utils import isqrt
        value = ids.value % PRIME
        assert value < 2 ** 250, f"value={value} is outside of the range [0, 2**250)."
        assert 2 ** 250 < PRIME
        ids.root = isqrt(value)
    %}
```

* Depends on functions:
    * `assert_nn_le`
    * `assert_in_range`

## func horner_eval
* Status:
* Assignee: 
* Hints:None 
* Depends on functions: None

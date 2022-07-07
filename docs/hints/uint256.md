
# uint256.cairo 

https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/uint256.cairo

This module requiere the following imports:
```
from starkware.cairo.common.bitwise import bitwise_and, bitwise_or, bitwise_xor
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_in_range, assert_le, assert_nn_le, assert_not_zero
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.pow import pow
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
```

## func uint256_check
* Depends on functions: None
* Hints: None

## func uint256_add
* Depends on functions: 
    * uint256_check
* Hints:
```
    %{
        sum_low = ids.a.low + ids.b.low
        ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
        sum_high = ids.a.high + ids.b.high + ids.carry_low
        ids.carry_high = 1 if sum_high >= ids.SHIFT else 0
    %}
```

## func split_64
* Depends on functions: None
* Hints:
```
    %{
        ids.low = ids.a & ((1<<64) - 1)
        ids.high = ids.a >> 64
    %}
```

## func uint256_mul
* Depends on functions: 
    * split_64
* Hints: Nne

## func uint256_sqrt{range_check_ptr}(n : Uint256) -> (res : Uint256):
* Depends on functions:
    * uint256_mul
    * uint256_le
    * uint256_add
    *uint256_sub
* Hints:
```
    %{
        from starkware.python.math_utils import isqrt
        n = (ids.n.high << 128) + ids.n.low
        root = isqrt(n)
        assert 0 <= root < 2 ** 128
        ids.root.low = root
        ids.root.high = 0
    %}
```

## func uint256_lt
* Depends on functions:
    * is_le(import)
* Hints: None

## func uint256_signed_lt
* Depends on functions:
    * uint256_add
    * uint256_lt
* Hints: None

## func uint256_le
* Depends on functions:
    * uint256_lt
* Hints: None

## func uint256_signed_le
* Depends on functions:
    * uint256_signed_lt
* Hints: None

## func uint256_signed_nn
* Depends on functions:
    * 
* Hints:
```
    %{ memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0 %}
```

## func uint256_signed_nn_le
* Depends on functions:
    * uint256_signed_le
    * uint256_signed_nn
* Hints:

## func uint256_unsigned_div_rem{range_check_ptr}
* Depends on functions:
    * uint256_mul
    * uint256_add
    * uint256_lt
* Hints:
```
    %{
        a = (ids.a.high << 128) + ids.a.low
        div = (ids.div.high << 128) + ids.div.low
        quotient, remainder = divmod(a, div)

        ids.quotient.low = quotient & ((1 << 128) - 1)
        ids.quotient.high = quotient >> 128
        ids.remainder.low = remainder & ((1 << 128) - 1)
        ids.remainder.high = remainder >> 128
    %}
```

## func uint256_not
* Depends on functions: None
* Hints: None

## func uint256_neg
* Depends on functions:
    * uint256_not
    * uint256_add
* Hints: None

## func uint256_cond_neg
* Depends on functions:
    * uint256_neg
* Hints: None

## func uint256_signed_div_rem
* Depends on functions:
    * uint256_neg
    * is_le
    * uint256_cond_neg
    * uint256_unsigned_div_rem
* Hints: None

## func uint256_sub
* Depends on functions:
    * uint256_neg
    * uint256_add
* Hints: None

## func uint256_eq:
* Depends on functions: None
* Hints: None

## func uint256_xor
* Depends on functions:
    * bitwise_xor
* Hints: None

## func uint256_and
* Depends on functions:
    * bitwise_and
* Hints: None

## func uint256_or
* Depends on functions:
    * bitwise_or
* Hints: None

## func uint256_pow2
* Depends on functions:
    * uint256_lt
    * is_le
    * pow
* Hints: None

## func uint256_shl
* Depends on functions:
    * uint256_pow2
    * uint256_mul
* Hints: None

## func uint256_shr
* Depends on functions:
    * uint256_pow2
    * uint256_unsigned_div_rem
* Hints: None

# func word_reverse_endian
* Depends on functions: None
* Hints: None

## func uint256_reverse_endian
* Depends on functions:
    * word_reverse_endian
* Hints: None
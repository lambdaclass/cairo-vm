# cairo_blake2s/blake2s.cairo
https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/cairo_blake2s/blake2s.cairo

This module requiere the following imports:
```
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_blake2s.packed_blake2s import N_PACKED_INSTANCES, blake2s_compress
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, split_felt, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.memset import memset
from starkware.cairo.common.pow import pow
from starkware.cairo.common.registers import get_fp_and_pc, get_label_location
from starkware.cairo.common.uint256 import Uint256
```

## func blake2s
* Depends on functions: 
    * blake2s_as_words
* Hints:None 

## func blake2s_bigend
* Depends on functions: 
    * blake2s
* Hints:None 

## func blake2s_as_words
* Depends on functions: 
    * blake2s_inner
* Hints:None 


## func blake2s_inner
* Depends on functions: 
    * is_le(import)
    * blake2s_last_block
    * memcpy(import)
* Hints:
```
        %{
        from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func
        compute_blake2s_func(segments=segments, output_ptr=ids.output)
    %}
```

## func blake2s_last_block
* Depends on functions: 
    * unsigned_div_rem(import)
    * memcpy(import)
    * memset(import)
* Hints:
```

        %{
        from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func
        compute_blake2s_func(segments=segments, output_ptr=ids.output)
    %}
```

## func finalize_blake2s
* Depends on functions: 
    * get_fp_and_pc(import)
    * _get_sigma()
    * unsigned_div_rem(import)
    * _finalize_blake2s_inner
* Hints:
```
    %{
        # Add dummy pairs of input and output.
        from starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress

        _n_packed_instances = int(ids.N_PACKED_INSTANCES)
        assert 0 <= _n_packed_instances < 20
        _blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)
        assert 0 <= _blake2s_input_chunk_size_felts < 100

        message = [0] * _blake2s_input_chunk_size_felts
        modified_iv = [IV[0] ^ 0x01010020] + IV[1:]
        output = blake2s_compress(
            message=message,
            h=modified_iv,
            t0=0,
            t1=0,
            f0=0xffffffff,
            f1=0,
        )
        padding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)
        segments.write_arg(ids.blake2s_ptr_end, padding)
    %}
```

## func _get_sigma():
* Depends on functions: 
    * get_label_location(import)
* Hints: None

## func _finalize_blake2s_inner:
* Depends on functions: 
    * alloc(import)
    * _pack_ints
    * blake2s_compress(import)
    * _finalize_blake2s_inner
* Hints: None

## func _pack_ints:
* Depends on functions: None
* Hints: None

## func blake2s_add_uint256:
* Depends on functions: None
* Hints:
```
    %{
        B = 32
        MASK = 2 ** 32 - 1
        segments.write_arg(ids.data, [(ids.low >> (B * i)) & MASK for i in range(4)])
        segments.write_arg(ids.data + 4, [(ids.high >> (B * i)) & MASK for i in range(4)])
    %}
```

## func blake2s_add_uint256_bigend:
* Depends on functions: None
* Hints:
```
    %{
        B = 32
        MASK = 2 ** 32 - 1
        segments.write_arg(ids.data, [(ids.high >> (B * (3 - i))) & MASK for i in range(4)])
        segments.write_arg(ids.data + 4, [(ids.low >> (B * (3 - i))) & MASK for i in range(4)])
    %}
```

## func blake2s_add_felt:
* Depends on functions: 
    * split_felt(import)
    * blake2s_add_uint256_bigend
    * blake2s_add_uint256
* Hints: None

## func blake2s_add_felts:
* Depends on functions: None
* Hints: None

## func blake2s_felts:
* Depends on functions: 
    * alloc(import)
    * blake2s_add_felts
    * blake2s
* Hints: None

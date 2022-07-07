# Implementation of cairo_keccak hints

 A summary of the cairo_keccak functions, hints used and function depedencies

 <https://github.com/starkware-libs/cairo-lang/tree/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/cairo_keccak>

## keccak.cairo

### func keccak_uint256s

* Hints: None
* Depends on functions:
  * `alloc`
  * `keccak`
  * `keccak_add_uint256s`

### func keccak_uint256s_bigend

* Hints: None
* Depends on functions:
  * `alloc`
  * `keccak_bigned`
  * `keccak_add_uint256s`

### func keccak_felts

* Hints: None
* Depends on functions:
  * `alloc`
  * `keccak`
  * `keccak_add_felts`

### func keccak_felts_bigend

* Hints: None
* Depends on functions:
  * `alloc`
  * `keccak_bigned`
  * `keccak_add_felts`

### func keccak_add_uint256

* Status:
* Asignee:
* Hints:

 ```
    %{
        segments.write_arg(ids.inputs, [ids.low % 2 ** 64, ids.low // 2 ** 64])
        segments.write_arg(ids.inputs + 2, [ids.high % 2 ** 64, ids.high // 2 ** 64])
    %}
 ```

* Depends on functions:
  * `uint256_reverse_endian` (from uint256.cairo)

### func keccak_add_felt

* Hints: None
* Depends on functions:
  * `split_felt` (from math.cairo)
  * `keccak_add_uint256`

### func keccak_add_felts

* Hints: None
* Depends on functions:
  * `keccak_add_felt`

### func keccak

* Hints: None
* Depends on functions:
  * `keccak_as_words`

### func keccak_bigend

* Hints: None
* Depends on functions:
  * `keccak`
  * `uint256_reverse_endian` (from uint256.cairo)

### func keccak_as_words

* Hints: None
* Depends on functions:
  * `alloc`
  * `_keccak`
  * `memset` (from memset.cairo)

### func prepare_block

* Hints: None
* Depends on functions:
  * `_copy_inputs`
  * `_padding`
  * `memcpy` (from memcpy.cairo)

### func _copy_inputs

* Status:
* Assignee:
* Hints:

 ```
 %{ ids.n_bytes < ids.BYTES_IN_WORD %}
 ```

* Depends on functions: None

### func _padding

* Hints: None
* Depends on functions:
  * `pow` (from pow.cairo)
  * `bitwise_xor` (from bitwise.cairo)
  * `_long_padding`

### func _long_padding

* Hints: None
* Depends on functions:
  * `memcpy` (from memcpy.cairo)
  * `bitwise_xor` (from bitwise.cairo)
  * `_long_padding`

### func _block_permutation

* Status:
* Assignee:
* Hints:

 ```
    %{
        from starkware.cairo.common.cairo_keccak.keccak_utils import keccak_func
        _keccak_state_size_felts = int(ids.KECCAK_STATE_SIZE_FELTS)
        assert 0 <= _keccak_state_size_felts < 100

        output_values = keccak_func(memory.get_range(
            ids.keccak_ptr - _keccak_state_size_felts, _keccak_state_size_felts))
        segments.write_arg(ids.keccak_ptr, output_values)
    %}
 ```

* Depends on functions: None

### func _keccak

* Hints: None
* Depends on functions:
  * `assert_nn_le` (from math.cairo)
  * `_block_permutation`
  * `_prepare_block`

### func finalize_keccak

* Status:
* Assignee:
* Hints:

 ```
    %{
        # Add dummy pairs of input and output.
        _keccak_state_size_felts = int(ids.KECCAK_STATE_SIZE_FELTS)
        _block_size = int(ids.BLOCK_SIZE)
        assert 0 <= _keccak_state_size_felts < 100
        assert 0 <= _block_size < 10
        inp = [0] * _keccak_state_size_felts
        padding = (inp + keccak_func(inp)) * _block_size
        segments.write_arg(ids.keccak_ptr_end, padding)
    %}
 ```

* Depends on functions: unsigned_div_rem

### func _finalize_keccak_inner

* Hints: None
* Depends on functions:
  * `packed_keccak_func`
  * `_prepare_block`

## packed_keccak.cairo

### func keccak_round

* Hints: None
* Depends on functions:None

### func packed_keccak_func

* Hints: None
* Depends on functions:None

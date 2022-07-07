# squash_dict.cairo functions
A summary of squash_dict.cairo functions, hints used and function dependencies 


https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/squash_dict.cairo

## func squash_dict:
* Hints:
```
    %{ vm_enter_scope() %}
```

```
    %{ vm_exit_scope() %}
```

```
    %{
        dict_access_size = ids.DictAccess.SIZE
        address = ids.dict_accesses.address_
        assert ids.ptr_diff % dict_access_size == 0, \
            'Accesses array size must be divisible by DictAccess.SIZE'
        n_accesses = ids.n_accesses
        if '__squash_dict_max_size' in globals():
            assert n_accesses <= __squash_dict_max_size, \
                f'squash_dict() can only be used with n_accesses<={__squash_dict_max_size}. ' \
                f'Got: n_accesses={n_accesses}.'
        # A map from key to the list of indices accessing it.
        access_indices = {}
        for i in range(n_accesses):
            key = memory[address + dict_access_size * i]
            access_indices.setdefault(key, []).append(i)
        # Descending list of keys.
        keys = sorted(access_indices.keys(), reverse=True)
        # Are the keys used bigger than range_check bound.
        ids.big_keys = 1 if keys[0] >= range_check_builtin.bound else 0
        ids.first_key = key = keys.pop()
    %}
```

* Depends on functions:
    * `squash_dict_inner`

## func squash_dict_inner:
* Hints:
```
    %{
        current_access_indices = sorted(access_indices[key])[::-1]
        current_access_index = current_access_indices.pop()
        memory[ids.range_check_ptr] = current_access_index
    %}
```

```
    %{ ids.should_skip_loop = 0 if current_access_indices else 1 %}
```

```
    %{
        new_access_index = current_access_indices.pop()
        ids.loop_temps.index_delta_minus1 = new_access_index - current_access_index - 1
        current_access_index = new_access_index
    %}
```

```
    %{ ids.loop_temps.should_continue = 1 if current_access_indices else 0 %}
```

```
    %{ assert len(current_access_indices) == 0 %}
```

```
    %{ assert ids.n_used_accesses == len(access_indices[key]) %}
```

```
    %{ assert len(keys) == 0 %}
```

```
    %{
        assert len(keys) > 0, 'No keys left but remaining_accesses > 0.'
        ids.next_key = key = keys.pop()
    %}
```

* Depends on functions:
    * `assert_lt_felt` (de `math`)
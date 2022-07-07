# Implementation of find_element.cairo hints

 A summary of the find_element.cairo functions, hints used and function depedencies

<https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/find_element.cairo>

### find_element

* Status:
* Asignee:
* Hints:

 ```
    %{
        array_ptr = ids.array_ptr
        elm_size = ids.elm_size
        assert isinstance(elm_size, int) and elm_size > 0, \
            f'Invalid value for elm_size. Got: {elm_size}.'
        key = ids.key

        if '__find_element_index' in globals():
            ids.index = __find_element_index
            found_key = memory[array_ptr + elm_size * __find_element_index]
            assert found_key == key, \
                f'Invalid index found in __find_element_index. index: {__find_element_index}, ' \
                f'expected key {key}, found key: {found_key}.'
            # Delete __find_element_index to make sure it's not used for the next calls.
            del __find_element_index
        else:
            n_elms = ids.n_elms
            assert isinstance(n_elms, int) and n_elms >= 0, \
                f'Invalid value for n_elms. Got: {n_elms}.'
            if '__find_element_max_size' in globals():
                assert n_elms <= __find_element_max_size, \
                    f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \
                    f'Got: n_elms={n_elms}.'

            for i in range(n_elms):
                if memory[array_ptr + elm_size * i] == key:
                    ids.index = i
                    break
            else:
                raise ValueError(f'Key {key} was not found.')
    %}

   ```

* Depends on functions:
  * `assert_nn_le` (from math.cairo)

### search_sorted_lower

* Status:
* Asignee:
* Hints:

   ```
    local index
    %{
        array_ptr = ids.array_ptr
        elm_size = ids.elm_size
        assert isinstance(elm_size, int) and elm_size > 0, \
            f'Invalid value for elm_size. Got: {elm_size}.'

        n_elms = ids.n_elms
        assert isinstance(n_elms, int) and n_elms >= 0, \
            f'Invalid value for n_elms. Got: {n_elms}.'
        if '__find_element_max_size' in globals():
            assert n_elms <= __find_element_max_size, \
                f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \
                f'Got: n_elms={n_elms}.'

        for i in range(n_elms):
            if memory[array_ptr + elm_size * i] >= ids.key:
                ids.index = i
                break
        else:
            ids.index = n_elms
    %}
   ```

* Depends on functions:
  * `assert_nn_le_felt` (from math.cairo)
  * `assert_nn_le` (from math.cairo)
  * `verify_multiplicity`

### search_sorted

* Hints: None
* Depends on functions:
  * `search_sorted_lower`

# Implementation of set.cairo hints

 A summary of the set.cairo functions, hints used and function depedencies

<https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/set.cairo>

### set_add

* Status:
* Asignee:
* Hints:

 ```
    %{
        assert ids.elm_size > 0
        assert ids.set_ptr <= ids.set_end_ptr
        elm_list = memory.get_range(ids.elm_ptr, ids.elm_size)
        for i in range(0, ids.set_end_ptr - ids.set_ptr, ids.elm_size):
            if memory.get_range(ids.set_ptr + i, ids.elm_size) == elm_list:
                ids.index = i // ids.elm_size
                ids.is_elm_in_set = 1
                break
        else:
            ids.is_elm_in_set = 0
    %}
 ```

* Depends on functions:
  * `memcpy` (from memcpy.cairo)
  * `assert_nn_le` (from math.cairo)

# default_dict.cairo functions
A summary of default_dict.cairo functions, hints used and function dependencies 


https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/default_dict.cairo

## func default_dict_new:
* Hints:
```
    %{
        if '__dict_manager' not in globals():
            from starkware.cairo.common.dict import DictManager
            __dict_manager = DictManager()

        memory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)
    %}
```
* Depends on functions: None

## func default_dict_finalize:
* Hints: None
* Depends on functions:
    * `dict_squash` (from `common.dict`)
    * `default_dict_finalize_inner`

## func default_dict_finalize_inner:
* Hints: None
* Depends on functions: None

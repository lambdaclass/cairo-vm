%builtins range_check

from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.dict import (
    dict_write,
    dict_update,
    dict_squash,
)
from starkware.cairo.common.default_dict import default_dict_new

func main{range_check_ptr}() -> ():
    let (dict_start) = default_dict_new(17)
    let dict_end = dict_start
    dict_write{dict_ptr=dict_end}(0, 1)
    dict_update{dict_ptr=dict_end}(0, 1, 2)
    dict_update{dict_ptr=dict_end}(0, 2, 3)
    dict_update{dict_ptr=dict_end}(0, 3, 4)
    let (squashed_dict_start, squashed_dict_end) = dict_squash{
        range_check_ptr=range_check_ptr
    }(dict_start, dict_end)
    assert squashed_dict_end.key = 0
    assert squashed_dict_end.prev_value = 1
    assert squashed_dict_end.new_value = 4
    return()
end

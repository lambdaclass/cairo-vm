pub(crate) const ADD_SEGMENT: &str = "memory[ap] = segments.add()";

pub(crate) const VM_ENTER_SCOPE: &str = "vm_enter_scope()";
pub(crate) const VM_EXIT_SCOPE: &str = "vm_exit_scope()";

pub(crate) const MEMCPY_ENTER_SCOPE: &str = "vm_enter_scope({'n': ids.len})";
pub(crate) const MEMCPY_CONTINUE_COPYING: &str = r#"n -= 1
ids.continue_copying = 1 if n > 0 else 0"#;

pub(crate) const MEMSET_ENTER_SCOPE: &str = "vm_enter_scope({'n': ids.n})";
pub(crate) const MEMSET_CONTINUE_LOOP: &str = r#"n -= 1
ids.continue_loop = 1 if n > 0 else 0"#;

pub(crate) const POW: &str = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1";

pub(crate) const IS_NN: &str =
    "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
pub(crate) const IS_NN_OUT_OF_RANGE: &str =
    "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
pub(crate) const IS_LE_FELT: &str = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
pub(crate) const IS_POSITIVE: &str = r#"from starkware.cairo.common.math_utils import is_positive
ids.is_positive = 1 if is_positive(
    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"#;

pub(crate) const ASSERT_NN: &str = r#"from starkware.cairo.common.math_utils import assert_integer
assert_integer(ids.a)
assert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"#;

pub(crate) const ASSERT_NOT_ZERO: &str = r#"from starkware.cairo.common.math_utils import assert_integer
assert_integer(ids.value)
assert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'"#;

pub(crate) const ASSERT_NOT_EQUAL: &str = r#"from starkware.cairo.lang.vm.relocatable import RelocatableValue
both_ints = isinstance(ids.a, int) and isinstance(ids.b, int)
both_relocatable = (
    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and
    ids.a.segment_index == ids.b.segment_index)
assert both_ints or both_relocatable, \
    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'
assert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"#;

pub(crate) const ASSERT_LE_FELT: &str = r#"from starkware.cairo.common.math_utils import assert_integer
assert_integer(ids.a)
assert_integer(ids.b)
a = ids.a % PRIME
b = ids.b % PRIME
assert a <= b, f'a = {a} is not less than or equal to b = {b}.'

ids.small_inputs = int(
    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"#;

pub(crate) const ASSERT_LT_FELT: &str = r#"from starkware.cairo.common.math_utils import assert_integer
assert_integer(ids.a)
assert_integer(ids.b)
assert (ids.a % PRIME) < (ids.b % PRIME), \
    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"#;

pub(crate) const SPLIT_INT_ASSERT_RANGE: &str =
    "assert ids.value == 0, 'split_int(): value is out of range.'";

pub(crate) const ASSERT_250_BITS: &str = r#"from starkware.cairo.common.math_utils import as_int

# Correctness check.
value = as_int(ids.value, PRIME) % PRIME
assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'

# Calculation for the assertion.
ids.high, ids.low = divmod(ids.value, ids.SHIFT)"#;

pub(crate) const SPLIT_INT: &str = r#"memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
assert res < ids.bound, f'split_int(): Limb {res} is out of range.'"#;

pub(crate) const SPLIT_64: &str = r#"ids.low = ids.a & ((1<<64) - 1)
ids.high = ids.a >> 64"#;

pub(crate) const SPLIT_FELT: &str = r#"from starkware.cairo.common.math_utils import assert_integer
assert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128
assert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW
assert_integer(ids.value)
ids.low = ids.value & ((1 << 128) - 1)
ids.high = ids.value >> 128"#;

pub(crate) const SQRT: &str = r#"from starkware.python.math_utils import isqrt
value = ids.value % PRIME
assert value < 2 ** 250, f"value={value} is outside of the range [0, 2**250)."
assert 2 ** 250 < PRIME
ids.root = isqrt(value)"#;

pub(crate) const UNSIGNED_DIV_REM: &str = r#"from starkware.cairo.common.math_utils import assert_integer
assert_integer(ids.div)
assert 0 < ids.div <= PRIME // range_check_builtin.bound, \
    f'div={hex(ids.div)} is out of the valid range.'
ids.q, ids.r = divmod(ids.value, ids.div)"#;

pub(crate) const SIGNED_DIV_REM: &str = r#"from starkware.cairo.common.math_utils import as_int, assert_integer

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

ids.biased_q = q + ids.bound"#;

pub(crate) const FIND_ELEMENT: &str = r#"array_ptr = ids.array_ptr
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
        raise ValueError(f'Key {key} was not found.')"#;

pub(crate) const SEARCH_SORTED_LOWER: &str = r#"array_ptr = ids.array_ptr
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
    ids.index = n_elms"#;

pub(crate) const SET_ADD: &str = r#"assert ids.elm_size > 0
assert ids.set_ptr <= ids.set_end_ptr
elm_list = memory.get_range(ids.elm_ptr, ids.elm_size)
for i in range(0, ids.set_end_ptr - ids.set_ptr, ids.elm_size):
    if memory.get_range(ids.set_ptr + i, ids.elm_size) == elm_list:
        ids.index = i // ids.elm_size
        ids.is_elm_in_set = 1
        break
else:
    ids.is_elm_in_set = 0"#;

pub(crate) const DEFAULT_DICT_NEW: &str = r#"if '__dict_manager' not in globals():
    from starkware.cairo.common.dict import DictManager
    __dict_manager = DictManager()

memory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)"#;

pub(crate) const DICT_NEW: &str = r#"if '__dict_manager' not in globals():
    from starkware.cairo.common.dict import DictManager
    __dict_manager = DictManager()

memory[ap] = __dict_manager.new_dict(segments, initial_dict)
del initial_dict"#;

pub(crate) const DICT_READ: &str = r#"dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
dict_tracker.current_ptr += ids.DictAccess.SIZE
ids.value = dict_tracker.data[ids.key]"#;

pub(crate) const DICT_WRITE: &str = r#"dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
dict_tracker.current_ptr += ids.DictAccess.SIZE
ids.dict_ptr.prev_value = dict_tracker.data[ids.key]
dict_tracker.data[ids.key] = ids.new_value"#;

pub(crate) const DICT_UPDATE: &str = r#"# Verify dict pointer and prev value.
dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
current_value = dict_tracker.data[ids.key]
assert current_value == ids.prev_value, \
    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'

# Update value.
dict_tracker.data[ids.key] = ids.new_value
dict_tracker.current_ptr += ids.DictAccess.SIZE"#;

pub(crate) const SQUASH_DICT: &str = r#"dict_access_size = ids.DictAccess.SIZE
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
ids.first_key = key = keys.pop()"#;

pub(crate) const SQUASH_DICT_INNER_SKIP_LOOP: &str =
    "ids.should_skip_loop = 0 if current_access_indices else 1";
pub(crate) const SQUASH_DICT_INNER_FIRST_ITERATION: &str = r#"current_access_indices = sorted(access_indices[key])[::-1]
current_access_index = current_access_indices.pop()
memory[ids.range_check_ptr] = current_access_index"#;

pub(crate) const SQUASH_DICT_INNER_CHECK_ACCESS_INDEX: &str = r#"new_access_index = current_access_indices.pop()
ids.loop_temps.index_delta_minus1 = new_access_index - current_access_index - 1
current_access_index = new_access_index"#;

pub(crate) const SQUASH_DICT_INNER_CONTINUE_LOOP: &str =
    "ids.loop_temps.should_continue = 1 if current_access_indices else 0";
pub(crate) const SQUASH_DICT_INNER_ASSERT_LEN_KEYS: &str = "assert len(keys) == 0";
pub(crate) const SQUASH_DICT_INNER_LEN_ASSERT: &str = "assert len(current_access_indices) == 0";
pub(crate) const SQUASH_DICT_INNER_USED_ACCESSES_ASSERT: &str =
    "assert ids.n_used_accesses == len(access_indices[key])";
pub(crate) const SQUASH_DICT_INNER_NEXT_KEY: &str = r#"assert len(keys) > 0, 'No keys left but remaining_accesses > 0.'
ids.next_key = key = keys.pop()"#;

pub(crate) const DICT_SQUASH_COPY_DICT: &str = r#"# Prepare arguments for dict_new. In particular, the same dictionary values should be copied
# to the new (squashed) dictionary.
vm_enter_scope({
    # Make __dict_manager accessible.
    '__dict_manager': __dict_manager,
    # Create a copy of the dict, in case it changes in the future.
    'initial_dict': dict(__dict_manager.get_dict(ids.dict_accesses_end)),
})"#;

pub(crate) const DICT_SQUASH_UPDATE_PTR: &str = r#"# Update the DictTracker's current_ptr to point to the end of the squashed dict.
__dict_manager.get_tracker(ids.squashed_dict_start).current_ptr = \
    ids.squashed_dict_end.address_"#;

pub(crate) const BIGINT_TO_UINT256: &str =
    "ids.low = (ids.x.d0 + ids.x.d1 * ids.BASE) & ((1 << 128) - 1)";
pub(crate) const UINT256_ADD: &str = r#"sum_low = ids.a.low + ids.b.low
ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
sum_high = ids.a.high + ids.b.high + ids.carry_low
ids.carry_high = 1 if sum_high >= ids.SHIFT else 0"#;

pub(crate) const UINT256_SQRT: &str = r#"from starkware.python.math_utils import isqrt
n = (ids.n.high << 128) + ids.n.low
root = isqrt(n)
assert 0 <= root < 2 ** 128
ids.root.low = root
ids.root.high = 0"#;

pub(crate) const UINT256_SIGNED_NN: &str =
    "memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0";

pub(crate) const UINT256_UNSIGNED_DIV_REM: &str = r#"a = (ids.a.high << 128) + ids.a.low
div = (ids.div.high << 128) + ids.div.low
quotient, remainder = divmod(a, div)

ids.quotient.low = quotient & ((1 << 128) - 1)
ids.quotient.high = quotient >> 128
ids.remainder.low = remainder & ((1 << 128) - 1)
ids.remainder.high = remainder >> 128"#;

pub(crate) const USORT_ENTER_SCOPE: &str =
    "vm_enter_scope(dict(__usort_max_size = globals().get('__usort_max_size')))";
pub(crate) const USORT_BODY: &str = r#"from collections import defaultdict

input_ptr = ids.input
input_len = int(ids.input_len)
if __usort_max_size is not None:
    assert input_len <= __usort_max_size, (
        f"usort() can only be used with input_len<={__usort_max_size}. "
        f"Got: input_len={input_len}."
    )

positions_dict = defaultdict(list)
for i in range(input_len):
    val = memory[input_ptr + i]
    positions_dict[val].append(i)

output = sorted(positions_dict.keys())
ids.output_len = len(output)
ids.output = segments.gen_arg(output)
ids.multiplicities = segments.gen_arg([len(positions_dict[k]) for k in output])"#;

pub(crate) const USORT_VERIFY: &str = r#"last_pos = 0
positions = positions_dict[ids.value][::-1]"#;

pub(crate) const USORT_VERIFY_MULTIPLICITY_ASSERT: &str = "assert len(positions) == 0";
pub(crate) const USORT_VERIFY_MULTIPLICITY_BODY: &str = r#"current_pos = positions.pop()
ids.next_item_index = current_pos - last_pos
last_pos = current_pos + 1"#;

pub(crate) const BLAKE2S_COMPUTE: &str = r#"from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func
compute_blake2s_func(segments=segments, output_ptr=ids.output)"#;

pub(crate) const BLAKE2S_FINALIZE: &str = r#"# Add dummy pairs of input and output.
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
segments.write_arg(ids.blake2s_ptr_end, padding)"#;

pub(crate) const BLAKE2S_ADD_UINT256: &str = r#"B = 32
MASK = 2 ** 32 - 1
segments.write_arg(ids.data, [(ids.low >> (B * i)) & MASK for i in range(4)])
segments.write_arg(ids.data + 4, [(ids.high >> (B * i)) & MASK for i in range(4)]"#;

pub(crate) const BLAKE2S_ADD_UINT256_BIGEND: &str = r#"B = 32
MASK = 2 ** 32 - 1
segments.write_arg(ids.data, [(ids.high >> (B * (3 - i))) & MASK for i in range(4)])
segments.write_arg(ids.data + 4, [(ids.low >> (B * (3 - i))) & MASK for i in range(4)])"#;

pub(crate) const NONDET_BIGINT3: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import split

segments.write_arg(ids.res.address_, split(value))"#;

pub(crate) const VERIFY_ZERO: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

q, r = divmod(pack(ids.val, PRIME), SECP_P)
assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
ids.q = q % PRIME"#;

pub(crate) const REDUCE: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

value = pack(ids.x, PRIME) % SECP_P"#;

pub(crate) const UNSAFE_KECCAK: &str = r#"from eth_hash.auto import keccak

data, length = ids.data, ids.length

if '__keccak_max_size' in globals():
    assert length <= __keccak_max_size, \
        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \
        f'Got: length={length}.'

keccak_input = bytearray()
for word_i, byte_i in enumerate(range(0, length, 16)):
    word = memory[data + word_i]
    n_bytes = min(16, length - byte_i)
    assert 0 <= word < 2 ** (8 * n_bytes)
    keccak_input += word.to_bytes(n_bytes, 'big')

hashed = keccak(keccak_input)
ids.high = int.from_bytes(hashed[:16], 'big')
ids.low = int.from_bytes(hashed[16:32], 'big')"#;

pub(crate) const UNSAFE_KECCAK_FINALIZE: &str = r#"from eth_hash.auto import keccak
keccak_input = bytearray()
n_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr
for word in memory.get_range(ids.keccak_state.start_ptr, n_elms):
    keccak_input += word.to_bytes(16, 'big')
hashed = keccak(keccak_input)
ids.high = int.from_bytes(hashed[:16], 'big')
ids.low = int.from_bytes(hashed[16:32], 'big')"#;

pub(crate) const IS_ZERO_NONDET: &str = "memory[ap] = to_felt_or_relocatable(x == 0)";
pub(crate) const IS_ZERO_PACK: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

x = pack(ids.x, PRIME) % SECP_P"#;
pub(crate) const IS_ZERO_ASSIGN_SCOPE_VARS: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P
from starkware.python.math_utils import div_mod

value = x_inv = div_mod(1, x, SECP_P)"#;

pub(crate) const DIV_MOD_N_PACKED_DIVMOD: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import N, pack
from starkware.python.math_utils import div_mod, safe_div

a = pack(ids.a, PRIME)
b = pack(ids.b, PRIME)
value = res = div_mod(a, b, N)"#;

pub(crate) const DIV_MOD_N_SAFE_DIV: &str = r#"value = k = safe_div(res * b - a, N)"#;
pub(crate) const GET_POINT_FROM_X: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

x_cube_int = pack(ids.x_cube, PRIME) % SECP_P
y_square_int = (x_cube_int + ids.BETA) % SECP_P
y = pow(y_square_int, (SECP_P + 1) // 4, SECP_P)

# We need to decide whether to take y or SECP_P - y.
if ids.v % 2 == y % 2:
    value = y
else:
    value = (-y) % SECP_P"#;

pub(crate) const EC_NEGATE: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

y = pack(ids.point.y, PRIME) % SECP_P
# The modulo operation in python always returns a nonnegative number.
value = (-y) % SECP_P"#;

pub(crate) const EC_DOUBLE_SCOPE: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
from starkware.python.math_utils import ec_double_slope

# Compute the slope.
x = pack(ids.point.x, PRIME)
y = pack(ids.point.y, PRIME)
value = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)"#;

pub(crate) const COMPUTE_SLOPE: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
from starkware.python.math_utils import line_slope

# Compute the slope.
x0 = pack(ids.point0.x, PRIME)
y0 = pack(ids.point0.y, PRIME)
x1 = pack(ids.point1.x, PRIME)
y1 = pack(ids.point1.y, PRIME)
value = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=SECP_P)"#;

pub(crate) const EC_DOUBLE_ASSIGN_NEW_X: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

slope = pack(ids.slope, PRIME)
x = pack(ids.point.x, PRIME)
y = pack(ids.point.y, PRIME)

value = new_x = (pow(slope, 2, SECP_P) - 2 * x) % SECP_P"#;

pub(crate) const EC_DOUBLE_ASSIGN_NEW_Y: &str =
    r#"value = new_y = (slope * (x - new_x) - y) % SECP_P"#;

pub(crate) const FAST_EC_ADD_ASSIGN_NEW_X: &str = r#"from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

slope = pack(ids.slope, PRIME)
x0 = pack(ids.point0.x, PRIME)
x1 = pack(ids.point1.x, PRIME)
y0 = pack(ids.point0.y, PRIME)

value = new_x = (pow(slope, 2, SECP_P) - x0 - x1) % SECP_P"#;

pub(crate) const FAST_EC_ADD_ASSIGN_NEW_Y: &str =
    r#"value = new_y = (slope * (x0 - new_x) - y0) % SECP_P"#;

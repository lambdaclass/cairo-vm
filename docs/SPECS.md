# Specifications

## Instructions
### Operations
Each Cairo instruction represents one of the following operations:

- `AddAP`: Increases the AP register.
- `AssertEq`: Asserts that two values are equal. Also used to write memory cells.
- `Call`:  A relative or absolute call.
- `Jnz`: A conditional jump.
- `Jump`: An unconditional jump.
- `Ret`: Returns from a call operation.

However, the binary encoding is not centered around the operation to perform, but around specific aspects of the instruction execution (i.e. how to modify the AP register).

### Encoding

The instruction encoding is specified in the [Cario whitepaper](https://eprint.iacr.org/2021/1063.pdf), page 32.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     off dst (biased representation)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                     off op0 (biased representation)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                     off op1 (biased representation)                     │
├─────┬─────┬───────────┬───────┬───────────┬─────────┬──────────────┬────┤
│ dst │ op0 │  op1 src  │  res  │ pc update │   ap    │    opcode    │ 0  │
│ reg │ reg │           │ logic │           │ update  │              │    │
├─────┼─────┼───┬───┬───┼───┬───┼───┬───┬───┼────┬────┼────┬────┬────┼────┤
│  0  │  1  │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │ 10 │ 11 │ 12 │ 13 │ 14 │ 15 │
└─────┴─────┴───┴───┴───┴───┴───┴───┴───┴───┴────┴────┴────┴────┴────┴────┘
```
The figure shows the structure of the 63-bit that form the first word of each instruction.
- The bits are ordered in a little-endian-like encoding, this implies that `off_dst` is located at bits `[0;15]`, while `dst_reg` is located at bit `48`.
- The last bit (`63`) is unused.

Each sets of fields determine different aspects of the instruction execution:
- `off_op0`, `off_op1`, `op0_reg`, `op1_src` determine the location of each operand.
- `off_dst`, `dst_reg` determine the location of the destionation.
- `res_logic` determine which operation to compute with the operands.
- `pc_update` determines how the PC register is updated.
- `ap_update` determines how the AP register is updated.
- `opcode` determines both how the FP register is updated, and how some memory cell values are deduced.

> [!NOTE]
> In our VM:
> - `off0` = `off_dst`
> - `off1` = `off_op0`
> - `off2` = `off_op1`

### Opcode Extensions

With the realease of Stwo, a new field was introduced named `opcode_extension`. Execution of instructions vary depending on its extension. The 4 types are `Stone`, `Blake`, `BlakeFinalize` and `QM31Operation`.

> [!NOTE]
> These are not specified on the whitepaper

#### Stone

This type is used when `opcode_extension == 0`. Its does not add new behaviour since its the original extension

#### Blake & BlakeFinalize

Blake is used when `opcode_extension == 1` and BlakeFinalize is used when `opcode_extension == 2` and they have some constraints, if these are not met while having one of the the blake extensions, the instructions becomes invalid:
- `opcode == 0` (no operation)
- `op1_src == 2` (FP) or `op1_src == 4` (AP)
- `res_logic == 0` (op1)
- `pc_update == 0` (Regular)
- `ap_update == 0` (Regular) || `ap_update == 2` (Add1)

After checking the constraints, if we are working with a `Blake` extension the blake2 algorithm is applied. The operands are contained as follows:
- `op0_addr` points to a sequence of 8  -> represents a state
- `op1_addr` points to a sequence of 16 felts -> represents a message
- `dst_addr` holds the value of the counter
- `ap` points to a sequence of 8 cells which each should either be uninitialised or already contain a value matching that of the output

The output consists of 8 felts that represent the output of the Blake2s compression.

On the other side, if we are working with the `BlakeFinalize` extension the operands are the same as with `Blake` with only one change:
- `op0_addr` points to a sequence of 9 felts -> first 8 felts represent the state the last one represents the state

The out here represents the Blake2s compression of the last block.

#### QM31

In this case, when `opcode_extension == 3` we are working with the `QM31Operation` which changes how the arithmetic (add, mul, sub, div) works on the VM by doing it with QM31 elements in reduced form. Again there are some constraints, if these are not met the instruction becomes invalid:
- `res_logic == 1` (Add) || `res_logic == 2` (Mul)
- `op1_src != 0` (Op0)
- `pc_update == 0` (Regular)
- `ap_update == 0` (Regular) || `ap_update == 2` (Add1)

### Auxiliary Variables

The instruction execution uses four auxiliary variables, that can be computed from the memory values, and the instruction fields:
- `dst`: Destination.
- `op0`: First operand.
- `op1`: Second operand.
- `res`: Operation result.

Depending on the instruction, the values of `dst`, `op0` and `op1` may be unknown at the start of execution, and will be deduced during it.

#### Computing `dst`

The value of `dst` is computed as the value at address `register + off_dst`, where `register` depends on the value of `dst_reg`:
- `dst_reg == 0`: We use `AP`.
- `dst_reg == 1`: We use `FP`.

If the value at the specified address is undefined, then it must be deduced instead.

#### Computing `op0`

The value of `op0` is computed as the value at address `register + off_op0`, where `register` depends on the value of `op0_reg`:
- `op0_reg == 0`: We use `AP`
- `op0_reg == 1`: We use `FP`.

If the value at the specified address is undefined, then it must be deduced instead.

#### Computing `op1`

The value of `op1` is computed as the value at address `base + off_op1`, where `base` depends on the value of `op1_src`:
- `op1_src == 0`: We use `op0`.
- `op1_src == 1`: We use `pc`.
- `op1_src == 2`: We use `FP`.
- `op1_src == 4`: We use `AP`.
- Otherwise: The instruction is invalid.

If the value at the specified address is undefined, then it must be deduced instead.

> [!NOTE]
> When `op1_src == 1` we must assert that `off_op1 == 1`, so that `op1` is an immediate value. This constraint is not specified in the whitepaper, but enforced by our VM.

#### Computing `res`

The variable `res` computation depends on `res_logic`.
- `res_logic == 0`:  We set `res = op1`.
- `res_logic == 1`:  We set `res = op0 + op1`.
- `res_logic == 2`:  We set `res = op0 * op1`.
- Otherwise: The instruction is invalid.

> [!NOTE] 
> The value of `res` won’t always be used. For example, it won’t be used when `pc_update == 4`.

### Additional Constraints

1. When `opcode == 1` (Call), the following conditions must be met:
- `off_dst == 0`
- `dst_reg == AP`
- `off_op0 == 1`
- `op0_reg == AP`
- `ap_update == 0` (add 2) 
- `op0 == PC + instruction_size`
- `FP == dst`

2. When `opcode == 2` (Return), the following conditions must be met:
- `off_dst == -2`
- `dst_reg == FP`
- `off_op1 == -1`
- `op1_src == FP`
- `res_logic == 0` (op1)
- `pc_update == 1` (absolute jump)

3. When `opcode == 4` (AssertEq), the following conditions must be met:
- `res == dst`


> [!NOTE]
> These constraints are not specified in the whitepaper, but enforced by our VM. If
> they are not met, then the instruction is **invalid**.

### Deductions

Some values may be undefined because the associated memory locations haven’t been set. In this case, they must be *deduced*, or *asserted*. 

An **assertion** verifies that two values are equal. This implies deducing one of the values if its undefined. When deducing a value, the corresponding memory cell must be updated with the deduced value.

If the memory cell corresponds to a builtin segment, the associated builtin runner should be used to assert the value of that memory cell.

Otherwise, the value will be deduced based on the `opcode`. There are 4 different types of operations:

- `opcode == 0`: A no-op (no operation).
- `opcode == 1`: A call operation.
    - Asserts that `op0 == pc + instruction_size`.
    - Asserts that `dst == fp`.
- `opcode == 2`: A ret operation.
- `opcode == 3`: An assert equal operation.
    - Asserts that `dst == res`. This may imply deducing `op0` value so that `res == dst`, by performing the inverse operation.

The `instruction_size` is always `1`, unless `op1` is an immediate, in which case it will be `2`.


> [!NOTE]
> If a value is undefined and cannot be deduced, the instruction execution must fail.
> This constraint is not specified in the whitepaper, but enforced by our VM.

### Updating Registers

At the end of the execution, the registers must be updated according to the instruction flags.

#### Updating the PC

The updated PC will be denoted by `next_pc`.

When updating the program counter, we depend primarily on the `pc_update` field:
- `pc_update == 0`: Advance program counter.
    - Set `next_pc = pc + instruction_size`.
- `pc_update == 1`: Absolute jump.
    - Set `next_pc = res`.
- `pc_update == 2`: Relative jump.
    - Set `next_pc = pc + res`.
- `pc_update == 4`: Conditional relative jump.
    - If `dst == 0`: Set `next_pc = pc + instruction_size`.
    - If `dst != 0`: Set `next_pc = pc + op1`.
- Otherwise: The instruction is invalid.

> [!NOTE]
> In our VM:
> `new_pc` = `next_pc`

#### Updating the AP

The updated AP will be denoted by `next_ap`.

When updating the allocation pointer, we depend primarily on the `ap_update` field, but also on the current operation:

- If the `opcode` is *call*, then we must assert that `ap_update == 0`:
    - Set `next_ap = ap + 2`
- Else, depending on `ap_update`.
    - `ap_update == 0`: Set `next_ap = ap`
    - `ap_update == 1`: Set `next_ap = ap + res`
    - `ap_update == 2`: Set `next_ap = ap + 1`
- Otherwise: The instruction is invalid.

> [!NOTE]
> In our VM:
> `new_apset` = `next_ap`

#### Updating the FP

The updated FP will be denoted by `next_fp`.

When updating the frame pointer, we depend on the `opcode`:

- `opcode == 0`: A no-op (no operation).
    - Set `next_fp = fp`.
- `opcode == 1`: A call operation.
    - Set `next_fp = ap + 2`.
- `opcode == 2`: A return operation.
    - Set `next_fp = dst`.
- `opcode == 3`: An assert equal operation.
    - Set `next_fp = fp`.
- Otherwise: The instruction is invalid.

> [!NOTE]
> In our VM:
> `new_fp_offset` = `next_fp`

## Memory Model

### Nondeterministic Memory

Cairo VM uses a Nondeterministic Read-Only memory model. This means - the prover chooses all the values of the memory, and the memory is immutable. The Cairo program may only read from it - Cairo Whitepaper section 2.6. 

### Memory Layout

Requirement 1: given a pair of accessed memory addresses *x and y*, any address *a* which satisfies that *x < a < y* must have also been accessed. This implies that any given set of accessed memory addresses must be contiguous.

#### Public Memory

After executing the cairo program and relocating the memory of the runner, that relocated memory is used to create a `PublicInput` which contains a vector of `PublicMemoryEntry`. Each of this contains a value, an address and its page, the whole vector represents the public memory.

### Memory Implementation

#### MemorySegmentManager

To satisfy requirement 1, Cairo organizes its memory into segments. In our VM we have the `MemorySegmentManager` which contains everything to manage this special parts of the memory.
- `segment_sizes`: A HashMap that contains the size of each segment
- `segment_used_sizes`: ??????????
- `memory`: The memory itself, containing the data, temporary data, relocation rules, among other things
- `public_memory_offsets`: ????????
- `zero_segment_index`: ????????
- `zero_segment_size`: ????????

#### Memory

The VM memory containing:
- `data`: A vector of vectors. Each vector representing a different `segment` with its own data
- `temp_data`: A vector of vector. Each vector representing a `temporary segment`
- `relocation_rules`: ??????
- `validated_addresses`: ??????
- `validation_rules`: ??????

#### MemoryCell & MaybeRelocatable

`MaybeRelocatable` represents a unit of data that can be a pointer or a felt:
- `RelocatableValue(Relocatable)`: Contains the segment index and the offset in that segment
- `Int(Felt252)`: Contains just a value of data 

`MemoryCell` represents a unit of data in the memory.

### Memory relationships

### Relocation

The memory relocation has the following steps:
- Compute the sizes of the segments in the memory
- Create the relocation table
- Relocate the memory (In cairo0 this depends on the config, but in cairo1 is always done)
- Relocate the trace

#### Memory Relocation

Segments from the memory are iterated in order and for each cell of a segment the new relocated address and value are calculated. With this, the continuous memory is created.

Each segment gets its index from the order they have in the data of `Memory`. The same happens with the `MemoryCells` in which their offset in the segment is represented by their index. For example:

```
Memory = [
    [Cell0, Cell1], # Segment0
    [Cell2],        # Segment1
    [Cell3]         # Segment2
]

Cell0 -> segment = 0 and offset = 0
Cell1 -> segment = 0 and offset = 1
Cell3 -> segment = 2 and offset = 0
```

- First we relocate the address as `relocation_table[segment] + offset`
- Then we relocate the value by turning a `MaybeRelocatable` into a `Felt252`:
    - If the cell is a `MaybeRelocatable::Int(n)`, then the new value is `num`.
    - If the cell is a `MaybeRelocatable::RelocatableValue(relocatable)`, then the new value is `relocation_table[relocatable.segment_index] + relocatable.offset`

> [!NOTE]
> In our VM:
> relocation mem starts at index 1

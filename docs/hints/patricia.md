# patricia.cairo functions
A summary of patricia.cairo functions, hints used and function dependencies 

https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/patricia.cairo

## func open_edge
* Hints: 
```
    %{
        ids.edge = segments.add()
        ids.edge.length, ids.edge.path, ids.edge.bottom = preimage[ids.node]
        ids.hash_ptr.result = ids.node - ids.edge.length
        if __patricia_skip_validation_runner is not None:
            # Skip validation of the preimage dict to speed up the VM. When this flag is set,
            # mistakes in the preimage dict will be discovered only in the prover.
            __patricia_skip_validation_runner.verified_addresses.add(
                ids.hash_ptr + ids.HashBuiltin.result)
    %}
```
* Depends on functions:
    * `assert_in_range`
    * `assert_lt_felt`


## func traverse_empty
* Hints: 
```
    %{
        from starkware.python.merkle_tree import decode_node
        left_child, right_child, case = decode_node(node)
        memory[ap] = 1 if case != 'both' else 0
    %}
```

```
    %{ vm_enter_scope(dict(node=left_child, **common_args)) %}
```

```
    %{ vm_exit_scope() %}
```

```
    %{ vm_enter_scope(dict(node=right_child, **common_args)) %}
```

```
    %{
        descend = descent_map.get((ids.height, ids.path))
        memory[ap] = 0 if descend is None else 1
    %}
```

```
    %{
        ids.child_bit = 0 if case == 'left' else 1
        new_node = left_child if case == 'left' else right_child
        vm_enter_scope(dict(node=new_node, **common_args))
    %}
```

```
    %{ memory[ids.siblings], ids.word = descend %}
```

```
    %{
        new_node = node
        for i in range(ids.length - 1, -1, -1):
            new_node = new_node[(ids.word >> i) & 1]
        vm_enter_scope(dict(node=new_node, **common_args))
    %}
```


* Depends on functions:
    * `assert_in_range`
    * `assert_lt_felt`

## func traverse_edge:
* Hints:

**(Repeated)**
```
    %{
        descend = descent_map.get((ids.height, ids.path))
        memory[ap] = 0 if descend is None else 1
    %}
```


```
    %{ ids.bit = (ids.edge.path >> ids.new_length) & 1 %}
```

```
    %{
        from starkware.python.merkle_tree import decode_node
        left_child, right_child, case = decode_node(node)
        memory[ap] = int(case != 'both')
    %}
```

**(Repeated)**
```
        %{ vm_enter_scope(dict(node=left_child, **common_args)) %}
```

**(Repeated)**
```
        %{ vm_exit_scope() %}
```

**(Repeated)**
```
        %{ vm_enter_scope(dict(node=right_child, **common_args)) %}
```

```
    %{ memory[ap] = int(case == 'right') ^ ids.bit %}
```

```
    %{
        new_node = left_child if ids.bit == 0 else right_child
        vm_enter_scope(dict(node=new_node, **common_args))
    %}
```

```
    %{
        ids.hash_ptr.x, ids.hash_ptr.y = preimage[ids.edge.bottom]
        if __patricia_skip_validation_runner:
            # Skip validation of the preimage dict to speed up the VM. When this flag is
            # set, mistakes in the preimage dict will be discovered only in the prover.
            __patricia_skip_validation_runner.verified_addresses.add(
                ids.hash_ptr + ids.HashBuiltin.result)
    %}
```

```
    %{ ids.length, ids.word = descend %}
```

**(Repeated)**
```
    %{
        new_node = node
        for i in range(ids.length - 1, -1, -1):
            new_node = new_node[(ids.word >> i) & 1]
        vm_enter_scope(dict(node=new_node, **common_args))
    %}
```

* Depends on functions:
    * `assert_in_range`
    * `assert_lt_felt`
    * `traverse_empty`
    * `hash2`

## func traverse_binary_or_leaf:
* Hints:

```
    %{
        from starkware.python.merkle_tree import decode_node
        left_child, right_child, case = decode_node(node)
        left_hash, right_hash = preimage[ids.node]

        # Fill non deterministic hashes.
        hash_ptr = ids.current_hash.address_
        memory[hash_ptr + ids.HashBuiltin.x] = left_hash
        memory[hash_ptr + ids.HashBuiltin.y] = right_hash

        if __patricia_skip_validation_runner:
            # Skip validation of the preimage dict to speed up the VM. When this flag is set,
            # mistakes in the preimage dict will be discovered only in the prover.
            __patricia_skip_validation_runner.verified_addresses.add(
                hash_ptr + ids.HashBuiltin.result)

        memory[ap] = int(case != 'both')
    %}
```

**(Repeated)**
```
    %{ vm_enter_scope(dict(node=left_child, **common_args)) %}
```

**(Repeated)**
```
    %{ vm_enter_scope(dict(node=right_child, **common_args)) %}
```

```
    %{ assert case == 'right' %}
```

* Depends on functions:
    * `traverse_non_empy`
    * `assert_not_zero`

## func traverse_node:
* Hints: None
* Depends on functions:
    * `traverse_empty`
    * `traverse_non_empty`

## func traverse_non_empty:
* Hints: 
```
    %{ memory[ap] = 1 if ids.height == 0 or len(preimage[ids.node]) == 2 else 0 %}
```

* Depends on functions:
    * `open_edge`
    * `traverse_edge`
    * `traverse_binary_or_leaf`

## func compute_pow2_array:
* Hints: None
* Depends on functions: None

## func patricia_update:
* Hints: None
* Depends on functions:
    * `patricia_update_constants_new`
    * `patricia_update_using_update_constants`

## func patricia_update_constants_new:
* Hints: None
* Depends on functions:
    * `compute_pow2_array`
    * `patricia_update_constants`

## func patricia_update_using_update_constants:
* Hints:
```

    %{
        from starkware.cairo.common.patricia_utils import canonic, patricia_guess_descents
        from starkware.python.merkle_tree import build_update_tree

        # Build modifications list.
        modifications = []
        DictAccess_key = ids.DictAccess.key
        DictAccess_new_value = ids.DictAccess.new_value
        DictAccess_SIZE = ids.DictAccess.SIZE
        for i in range(ids.n_updates):
            curr_update_ptr = ids.update_ptr.address_ + i * DictAccess_SIZE
            modifications.append((
                memory[curr_update_ptr + DictAccess_key],
                memory[curr_update_ptr + DictAccess_new_value]))

        node = build_update_tree(ids.height, modifications)
        descent_map = patricia_guess_descents(
            ids.height, node, preimage, ids.prev_root, ids.new_root)
        del modifications
        __patricia_skip_validation_runner = globals().get(
            '__patricia_skip_validation_runner')

        common_args = dict(
            preimage=preimage, descent_map=descent_map,
            __patricia_skip_validation_runner=__patricia_skip_validation_runner)
        common_args['common_args'] = common_args
    %}
```

```
    %{ vm_enter_scope(dict(node=node, **common_args)) %}
```

**(Repeated)**
```
    %{ vm_exit_scope() %}
```
* Depends on functions:
    * `assert_le`
    * `traverse_node`
    * `alloc`







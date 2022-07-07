# Implementation of usort.cairo hints

 A summary of the usort.cairo functions, hints used and function depedencies

<https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/usort.cairo>

### usort

* Status:
* Asignee:
* Hints:

 ```
    %{ vm_enter_scope(dict(__usort_max_size = globals().get('__usort_max_size'))) %}
    
 ```

  ```
      %{
        from collections import defaultdict

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
        ids.multiplicities = segments.gen_arg([len(positions_dict[k]) for k in output])
    %}
   ```

   ```
   %{ vm_exit_scope() %}
   ```

* Depends on VirtualMachine methods:
  * `vm_enter_scope`
  * `vm_exit_scope`

### verify_usort

* Status:
* Asignee:
* Hints:

   ```
    %{
        last_pos = 0
        positions = positions_dict[ids.value][::-1]
    %}
   ```

* Depends on functions:
  * `assert_lt` (from math.cairo)
  * `assert_nn` (from math.cairo)
  * `verify_multiplicity`

### verify_multiplicity

* Status:
* Asignee:
* Hints:
*

   ```
   %{ assert len(positions) == 0 %}
   ```

   ```
    %{
        current_pos = positions.pop()
        ids.next_item_index = current_pos - last_pos
        last_pos = current_pos + 1
    %}
   ```

* Depends on functions:
  * `assert_nn` (from math.cairo)

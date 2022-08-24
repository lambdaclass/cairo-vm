How to run a cairo program with custom hints
====

### Step by Step Guide:

#### Step 1: Add cairo-rs to your project as a crate

Cargo.toml

```rust
[dependencies]
cairo-rs =  {path = "[path to cairo-rs directory"}
```
#### Step 2: Code the implementation of your custom hint (Using the helpers and proxies described in the sections below)
For this step, you will have to code your hint implementation as a closure, and then wrap it inside a Box (smart pointer), and a HintFunc (type alias for hint functions).
Note: The reason for using a closure is due to the functions being Fn trait objects, more on this from the [rust documentation](https://doc.rust-lang.org/std/ops/trait.Fn.html). The hint implementation must also follow a specific structure in terms of variable input and output:
```rust
HintFunc(Box::new(
        |vm_proxy: &mut VMProxy,
         _exec_scopes_proxy: &mut ExecutionScopesProxy,
         ids_data: &HashMap<String, HintReference>,
         ap_tracking: &ApTracking|
         -> Result<(), VirtualMachineError> {
            //Your implementation
        },
```

For example, this function implements the hint "print(ids.a)":

```rust
let hint_func: HintFunc = HintFunc(Box::new(
        |vm_proxy: &mut VMProxy,
         _exec_scopes_proxy: &mut ExecutionScopesProxy,
         ids_data: &HashMap<String, HintReference>,
         ap_tracking: &ApTracking|
         -> Result<(), VirtualMachineError> {
            let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
            println!("{}", a);
            Ok(())
        },
    ));
```

#### Step 3: Instantiate the BuiltinHintProcessor and add your custom hint implementation
Import the BuiltinHintProcessor from cairo-rs, instantiate it using the `new_empty()` method and the add your custom hint implementation using the method `add_hint`
```rust
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor

let mut hint_processor = BuiltinHintProcessor::new_empty();
hint_processor.add_hint(String::from("print(ids.a)"), hint_func);
```
You can also create a dictionary of HintFunc and use the method `new()` to create a BuiltinHintProcessor with a preset dictionary of functions instead of using `add_hint()` for each custom hint.

#### Step 4: Run your cairo program using your modified BuiltinHintProcessor
Import the function cairo_run from cairo-rs, and run your compiled program

```rust
use cairo_rs::cairo_run::cairo_run;
cairo_run(
        Path::new("custom_hint.json"),
        "main",
        false,
        &hint_processor,
    )
    .expect("Couldn't run program");
```
#### Final notes:

The example used in this guide can be found [here](../../../custom_hint_example/).
The example can be ran using `make example`

### How to code your hint implementation:
In order to cdoe your custom hints you need to take into account the accessible data and the existing helpers.

### Data which can be accessed by hint functions:

* Proxy structures:
  * `exec_scopes_proxy` is the hint's gateaway to interact with the execution_scopes in the VM and share data bewteen hints without inserting them into the cairo execution. It provides methods to create and remove scopes and to modify the current scope, along with several helper methods to allow inserting and retrieving variables of specific types. This proxy only allows modifying the current scope, which is the last available scope before the hint's execution (Note that calling enter_scope and exit_scope wont change the current scope for the duration of the hint´s execution)
  * `vm_proxy` is the hint's gateway to the internal values of the VM, it provides mutable references to the memory segment manager and the run context, and immutable references to the builtin runners and the program's prime, it also contains a memory proxy:
  * `MemoryProxy`: It grants a more limited access to the VM's memory, providing the necessary methods to modify it in a controlled manner.

* ids_data: A dictionary maping ids names to their references
* ap_tracking: Ap tracking data of the hint
These last two structures are used by helper functions to manage variables from the cairo scope, and can be overlooked when coding your custom hints.


### Helper functions

There are many helper functions available [here](../../../src/hint_processor/builtin_hint_processor/hint_utils.rs), that will allow you to easily manage cairo variables:

* get_integer_from_var_name
* get_ptr_from_var_name
* compute_addr_from_var_name
* insert_value_from_var_name
* insert_value_into_ap

These methods take the name of the ids variable along with vm_proxy, ids_data and ap_tracking and provide .

Note: When handling pointer type variables, computing the address and using it to get the variable from memory might not lead to the correct value (as the variable refrence may contain an immediate value that has to be added to the ptr itself), so using the functiom `get_ptr_from_var_name` is strongly recomended.
Note: Cairo's memory is write-once, read-only, so when using `insert_value_from_var_name` its important to first make sure that the variable doesnt contain any value (for example, it may be defined as local but never written) to avoid inconsistent memory errors

There are also some helpers that dont depend on the hint processor used that can also be used to simplify coding hints [here](../../../src/hint_processor/hint_processor_utils.rs):

* get_range_check_builtin
* bigint_to_usize
* bigint_to_u32

### Error Handling

This api uses VirtualMachineError as error resturn type for hint functions, while its not possible to add error types to VirtualMachineError, you can use VirtualMachineError::CustomHint which receives a string and prints an error message with the format: "Custom Hint Error: [your message]".
For example, if we want our hint to return an error if ids.a is less than 0 we could write:

```rust
if (get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)? < 0){
  return Err(VirtualMachineError::CustomHint(String::from("a < 0")))
}
```

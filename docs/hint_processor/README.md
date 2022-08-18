Custom Hint Processor
===

In order to customize the processing of hints in the Cairo Rust VM, users can create their own hint processor implementing the trait HintProcessor.

## How does the HintProcessor work?

In order to implement the trait, the processor must implement two methods: `compile_hint`, and `execute_hint`.
Note: The trait itself is defined in hint_processor_definition.rs

### `compile_hint`

This method is called before the execution phase of the VM.
It receives the Hint's data:

* The hint code as a String
* A map from variable name (note that this contains the full path of the variable, ie "__main__.a", instead of just the variable name "a") to reference id number
* A map of all the variable references (as a HintReference struct) by id (this id corresponds to the reference id number in the previous map)
* The hint's ap tracking data.
And it returns a dynamic structure, that will then be used by execute Hint.
The purpose of this method is to organize the data related to hints in the way it should be used by the processor to execute the hint.

### `execute_hint`

This method is called at the start of each VM step when there is a hint to execute.
It receives the dynamic structure created by `compile_hint` along with a set of proxies containing a limited access to the VM's Internals:

* `exec_scopes_proxy` is the hint's gateaway to interact with the execution_scopes in the VM and share data bewteen hints without inserting them into the cairo execution. It provides methods to create and remove scopes and to modify the current scope, along with several helper methods to allow inserting and retrieving variables of specific types. This proxy only allows modifying the current scope, which is the last available scope before the hint's execution (Note that calling enter_scope and exit_scope wont change the current scope for the duration of the hint´s execution)
* `vm_proxy` is the hint's gateway to the internal values of the VM, it provides mutable references to the memory segment manager and the run context, and immutable references to the builtin runners and the program's prime, it also contains a memory proxy:
* `MemoryProxy`: It grants a more limited access to the VM's memory, providing the necessary methods to modify it in a controlled manner.
The purpose of this method is to carry out the execution of the hint, given the data from `compile_hint`

## Managing Cairo variables inside hint execution

Each variable's addresse and value can be computed with the information provided by the data in the HintReference structure + the hint's ap tracking data.
The following helper functions are provided in hint_processor_utils.rs to simplify variable management:

* get_integer_from_reference
* get_ptr_from_reference
* compute_addr_from_reference
* insert_value_from_reference

These methods take the HintReference associated to the variable along with the hint's ApTracking data.
Note: When handling pointer type variables, computing the address and using it to get the variable from memory might not lead to the correct value (as the variable refrence may contain an immediate value that has to be added to the ptr itself), so using the functiom get_ptr_from_reference is strongly recomended.
Note: Cairo's memory is write-once, read-only, so when using `insert_value_from_reference` its important to first make sure that the variable doesnt contain any value (for example, it may be defined as local but never written) to avoid inconsistent memory errors

## BuiltinHintProcessor

The BuiltinHintProcessor is the default hint exector of the VM, it is able to execute hints from the common library + sha256

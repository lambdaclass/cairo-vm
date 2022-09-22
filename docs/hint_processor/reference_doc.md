
# HintProcessor trait
Hints are a vital part of Cairo for achieving its non-determinism. In cairo-rs, they can be executed by any `struct` that implements the `HintProcessor` trait found in `src/hint_processor/hint_processor_definition.rs`.
This trait implies the definition of two functions:

* `fn compile_hint(
        &self,
        hint_code: &str,
        ap_tracking_data: &ApTracking,
        reference_ids: &HashMap<String, usize>,
        references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError>;`: Transforms hint data outputted by the VM into whichever format will be later used by execute_hint.
    
* `fn execute_hint(&self, 
        vm_proxy: &mut VMProxy,
        exec_scopes_proxy: &mut ExecutionScopesProxy,
        hint_data: &Box<dyn Any>,) -> Result<(), VirtualMachineError>`: Executes the hint which data is provided by a dynamic structure previously created by compile_hint.
        
## How do we implement this trait?
Cairo-rs provides a series of interfaces used by `compile_hint()` and `execute_hint()` implementations.

### ApTracking
```rust
pub struct ApTracking {
    pub group: usize,
    pub offset: usize,
}
```
Contains the group and the offset corresponding to the hint, which are used to compute addresses.

### HintReference
```rust
pub struct HintReference {
    pub register: Option<Register>,
    pub offset1: i32,
    pub offset2: i32,
    pub dereference: bool,
    pub inner_dereference: bool,
    pub ap_tracking_data: Option<ApTracking>,
    pub immediate: Option<BigInt>,
}
```
This represents the reference corresponding to each ids, which will later be accessible from the hint functions.

### VMProxy
```rust
pub struct VMProxy<'a> {
    pub memory: MemoryProxy<'a>,
    pub segments: &'a mut MemorySegmentManager,
    pub run_context: &'a mut RunContext,
    pub builtin_runners: &'a Vec<(String, Box<dyn BuiltinRunner>)>,
    pub prime: &'a BigInt,
}
```
A `struct` representing limited access to the VM's internal values and structures.
### ExecutionScopesProxy
```rust
pub struct ExecutionScopesProxy<'a> {
    scopes: &'a mut ExecutionScopes,
    current_scope: usize,
}
```
Structure representing a limited access to the execution scopes.
It allows adding and removing scopes, but will only allow modifications to the last scope present before hint execution using its implementation.

## A more detailed look at BuiltinHintProcessor
As an example for `HintProcessor` trait implementation we can take a look at how `BuiltinHintProcessor` implements those methods step by step.

#### `fn compile_hint(...)`
```rust
...    
    fn compile_hint(
        &self,
        code: &str,
        ap_tracking: &ApTracking,
        reference_ids: &HashMap<String, usize>,
        references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        Ok(any_box!(HintProcessorData {
            code: code.to_string(),
            ap_tracking: ap_tracking.clone(),
            ids_data: get_ids_data(reference_ids, references)?,
        }))
    }
...
```
As we can see, `compile_hint()` generates `HintProcessorData` by wrapping the code, the ap tracking and the ids data, which is taken from `references` using the keys taken from `reference_ids`. Then, `any_box()!` macro wraps it with a Box and then casts it as a `Box<dyn Any>`. 

#### `fn execute_hint(...)`
```rust
...    
    fn execute_hint(
        &self,
        vm_proxy: &mut VMProxy,
        exec_scopes_proxy: &mut ExecutionScopesProxy,
        hint_data: &Box<dyn Any>,
    ) -> Result<(), VirtualMachineError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;

        if let Some(hint_func) = self.extra_hints.get(&hint_data.code) {
            return hint_func.0(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            );
        }

        match &*hint_data.code {
            hint_code::ADD_SEGMENT => add_segment(vm_proxy),
...
```
Hint data is cast back to a `HintProcessorData` reference. I a function that was previously added to the HintProcessor is found in the hint code, it's called and it's return value is returned as the result of the current hint. If not, the code is matched against predefined instructions(`&str`) so that they can be executed.
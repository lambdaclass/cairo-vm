How to add new hints to our BuiltinHintProcessor
====

### How does our BuiltinHintProcessor execute hints?
Our BuiltinHintProcessor executes hints by matching the hint code to the appropiate function (which implements the hint logic)

### What can the functions that implement hints access?
* Proxy structures: as described in [Custom Hint Processor](../../hint_processor/)

* Hint data: A structure containing the following data related to hints:
  * code: The hint's code in String format
  * ap_tracking: Ap tracking data of the hint
  * ids data: A dictionary maping ids names to their references

## Helper methods:
The helper methods defined in [hint_processor_utils.rs](../../../src/hint_processor/hint_processor_utils.rs) can be used along with the processor's own helpers in  [hint_utils.rs](../../../src/hint_processor/builtin_hint_processor/hint_utils.rs) which can manipulate variables using their name.

## How can I add my own hints?
In order to add more hints to the BuiltinHintExecutor, you should code the hint's logic in rust using the above mentioned data + helpers, and then add an arm to the match expression in execute_hint [builtin_hint_processor_definition.rs](../../../src/hint_processor/builtin_hint_processor/builtin_hint_processor_definition.rs) matching the custom hint's code (as written in the cairo program) to the implemented function.
The [builtin_hint_processor](../../../src/hint_processor/builtin_hint_processor) folder contains implementations for several library hints, which can be used as examples when coding your custom hints.


LambdaClass - StarkWare
# Cairo-rs - Python FFI integration
#### 20th September 2022

### OVERVIEW
In order to allow cairo-rs to execute any python code embedded into a Cairo program and to allow a Python context to call cairo-rs, we are adding support to provide communication of the VM state between Rust and Python via FFI bindings using PyO3, as an external crate. 

### GOAL
* Be able to efficiently and conveniently allow interactions between Python and cairo-rs. 
* Have an external crate which encapsulates the python hint execution, and which is able to both run Cairo-rs, and be imported as a python module so that the VM can be ran from a python process.

### SPECIFICATION
* A cairo-rs VM with the builtin hint processor enabled can include another fallback hint processor to execute hints not implemented by the builtin hint processor. 
* FFI integration and functionality will be encapsulated in a crate external to cairo-rs.
* Variables defined by a hint can only be accessed by hints written in the same language, i.e., Rust hints are aware only of variables defined by Rust hints and Python hints are aware only of variables defined by Python hints.
* Python hints are supported when running the cairo-rs standalone binary (as opposed to importing it from Python) only with the CPython interpreter.
* The Cairo-rs VM can be instantiated by a Rust program, still allowing python hints in cairo programs.
* The Cairo-rs VM can be instantiated by a Python interpreter as a regular object. 
* A Rust or Python program can instantiate one or more independent cairo-rs VMs, allowing for multiple coexisting VMs.
* When instantiated by a Python interpreter, that same interpreter will be used to execute Python hints, i.e. python hints have limited access to the running context (code paths, modules, scopes created by previous hints).
* An instance of a cairo-rs VM will be running either a cairo program interpretation loop or a python hint, but not both at the same time.
	* i.e. hints do not run concurrently 
	* The VM state shared with hints can only be accessed by a single hint at a time.
	* The VM memory is private to a VM instance and cannot be shared across differents VM instances.
* Hint interaction with the VM will be restricted to:
	* read-write access to memory (with the methods __setitem__ and  __getitem__),
	* segments manager (with the methods add and write_arg),
	* ids (with the methods __setattr__ and __getattr__),
	* hint execution scopes,
	* and read-only access to ap and fp registers.


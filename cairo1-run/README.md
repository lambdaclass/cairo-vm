# Cairo1-run

A cairo-vm crate to run Cairo 1 Programs

Once you are inside the `./cairo1-run` folder, use the CLI with the following commands

To install the required dependencies(cairo corelib) run

```bash
make deps 
```

Now that you have the dependencies necessary to run the tests, you can run:

```bash
make test
```

To execute a cairo 1 program

```bash
cargo run ../cairo_programs/cairo-1-programs/fibonacci.cairo 
```

Arguments to generate the trace and memory files

```bash
cargo run ../cairo_programs/cairo-1-programs/fibonacci.cairo --trace_file ../cairo_programs/cairo-1-programs/fibonacci.trace --memory_file ../cairo_programs/cairo-1-programs/fibonacci.memory
```

To pass arguments to `main`

* Separate arguments with a whitespace inbetween
* In order to pass arrays, wrap array values between brackets

Example:

```bash

cargo run ../cairo_programs/cairo-1-programs/with_input/array_input_sum.cairo --layout all_cairo --args '2 [1 2 3 4] 0 [9 8]'

```

To execute all the cairo 1 programs inside `../cairo_programs/cairo-1-programs/` and generate the corresponding trace and the memory files

```bash
make run 
```

## CLI argument list

The cairo1-run cli supports the following optional arguments:

* `--layout <LAYOUT>`: Sets the layout for the cairo_run. This will limit the available builtins. The deafult layout is `plain`, which has no builtins. For general purpose, the `all_cairo` layout contains all currently available builtins. More info about layouts [here](https://www.cairo-lang.org/docs/how_cairo_works/builtins.html#layouts).

* `--args <ARGUMENTS>`: Receives the arguments to be passed to the program's main function. Receives whitespace-separated values which can be numbers or arrays, with arrays consisting of whitespace-separated numbers wrapped between brackets

* `--trace_file <TRACE_FILE>`: Receives the name of a file and outputs the relocated trace into it

* `--memory_file <MEMORY_FILE>`: Receives the name of a file and outputs the relocated memory into it

* `--proof_mode`: Runs the program in proof_mode

* `--air_public_input <AIR_PUBLIC_INPUT>`: Receives the name of a file and outputs the AIR public inputs into it. Can only be used if proof_mode is also enabled.

* `--air_private_input <AIR_PRIVATE_INPUT>`: Receives the name of a file and outputs the AIR private inputs into it. Can only be used if proof_mode, trace_file & memory_file are also enabled.

* `--cairo_pie_output <CAIRO_PIE_OUTPUT>`: Receives the name of a file and outputs the Cairo PIE into it. Can only be used if proof_mode, is not enabled.

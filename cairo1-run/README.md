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

cargo run ../cairo_programs/cairo-1-programs/array_input_sum.cairo --args '2 [1 2 3 4] 0 [9 8]'

```

To execute all the cairo 1 programs inside `../cairo_programs/cairo-1-programs/` and generate the corresponding trace and the memory files

```bash
make run 
```

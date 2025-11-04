# Demo of `cairo-vm` on WebAssembly (Cairo 1)

While cairo-vm is compatible with WebAssembly, it doesn't implement any bindings to it.
Instead, create a new WebAssembly crate with cairo-vm and cairo1-run as dependencies and implement the required functionality there.

Since mimalloc is not automatically compilable to WebAssembly, the cairo-vm dependency should disable the default features, which will in turn disable mimalloc. Simliar to this, WebAssembly is
not compatible with rust standard library. For this reason, cairo1-run should also disable the default features.

A working example is provided in this repository.

## Dependencies

To compile and run the example you need:

- a Cairo 1 or Cairo 2 compiler
- the _wasm-pack_ crate
- some HTTP server (for example: the `live-server` npm module)

> **Note**
> The first two dependencies can be installed via the repository's installation script (see ["Installation script"](../../README.md#installation-script))

## Building

To build the example, first you need to compile your Cairo Program, using either cairo 1 or cairo 2 compiler:

If cairo 1 is used:

```sh
cairo-compile -rs ../../cairo_programs/cairo-1-programs/bitwise.cairo ../../cairo_programs/cairo-1-programs/bitwise.sierra
```

If cairo 2 is used:

```sh
cairo-compile -r ../../cairo_programs/cairo-1-programs/bitwise.cairo ../../cairo_programs/cairo-1-programs/bitwise.sierra
```

> WARNING: This example uses `cairo1-run::cairo_run_program` which expectes the program to be compiled with debug names. By default, `cairo-compile` does not include debug names in sierra. Due to this, the flag `-r` or `--replace-ids` is needed.

compile the WebAssembly package:

```sh
wasm-pack build --target=web
```

This will generate a javascript module that is directly loadable by the browser.

## Running

To run the example webpage, you need to run an HTTP server.
For example, using the _live-server_ npm module:

```sh
# while in <repo>/examples/wasm-demo-cairo1
npx live-server
```

> **Warning**
> Trying to run `index.html` directly (i.e. URL starts with `file://`) will result in a CORS error.

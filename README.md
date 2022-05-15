# Cleopatra Cairo VM

Cleaopatra is a Rust implementation of the Cairo VM.

## Cairo

* From Cairo Documentation: [How Cairo Works](https://www.cairo-lang.org/docs/how_cairo_works/index.html#how-cairo-works)

* [Cairo VM code](https://github.com/starkware-libs/cairo-lang/tree/master/src/starkware/cairo/lang/vm)

* [Cairo Whitepaper](https://eprint.iacr.org/2021/1063)

* [Cairo Verifier](https://github.com/patrickbiel01/Cairo_Verifier) in Rust


## Flow Diagram

We've created a diagram that illustrates function calls and where each of them are defined for a simple cairo program execution.

<p float="left">
  <img src="./docs/diagram/cairo_vm_color_key.png" width="200" />
</p>

![diagram](./docs/diagram/cairo_vm_flow_diagram.jpg)

This diagram was produced using this [mermaid code](./docs/diagram/cairo_vm_flow_diagram.md).

## Original Cairo VM Internals

We wrote a document explaining how the Cairo VM works. It can be found [here](./docs/README.md).

## Compilers

* [Introduction to Compilers and Language Design - Douglas Thain](http://compilerbook.org)
* [Crafting interpreters - Robert Nystrom](https://craftinginterpreters.com)

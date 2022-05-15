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

## Compilers and interpreters

These is a list of recommended books to learn how to implement a compiler or an interpreter.

* [Introduction to Compilers and Language Design - Douglas Thain](http://compilerbook.org)
* [Beautiful Racket - Matthew Flatt](https://beautifulracket.com)
* [Crafting interpreters - Robert Nystrom](https://craftinginterpreters.com)
* [Engineering a Compiler - Keith D. Cooper, Linda Torczon](https://www.goodreads.com/en/book/show/1997607.Engineering_a_Compiler)

## Zero Knowledge Proofs

### Basics
* [Intro to zero knowledge proofs](https://www.youtube.com/watch?v=HUs1bH85X9I)
* [Security and Privacy for Crypto with Zero-Knowledge Proofs](https://www.youtube.com/watch?v=3NL0ThdvWMU)
* [A Hands-On Tutorial for Zero-Knowledge Proofs Series](http://www.shirpeled.com/2018/09/a-hands-on-tutorial-for-zero-knowledge.html)

### ZK SNARKs
* [What are zk-SNARKs?](https://z.cash/technology/zksnarks/)
* [Vitalik's introduction to how zk-SNARKs are possible](https://vitalik.ca/general/2021/01/26/snarks.html)
* [Vitalik's post on quadratic arithmetic programs](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649)
* [Comparing General Purpose zk-SNARKs](https://medium.com/coinmonks/comparing-general-purpose-zk-snarks-51ce124c60bd)
* [Dark forest's intro + circuits PARRT 1](https://blog.zkga.me/intro-to-zksnarks)
* [Dark forest's intro + circuits PARRT 2](https://blog.zkga.me/df-init-circuit)

### ZK STARKs
* [Cryptography Stack Exchange Answer](https://crypto.stackexchange.com/questions/56327/what-are-zk-starks)
* [Hasu gets STARK-pilled - with Eli Ben-Sasson](https://youtu.be/-6BtBUbiUIU)
* [STARKs, Part I: Proofs with Polynomials](https://vitalik.ca/general/2017/11/09/starks_part_1.html)
* [STARKs, Part II: Thank Goodness It's FRI-day](https://vitalik.ca/general/2017/11/22/starks_part_2.html)
* [STARKs, Part 3: Into the Weeds](https://vitalik.ca/general/2018/07/21/starks_part_3.html)
* [StarkDEX Deep Dive: the STARK Core Engine](https://medium.com/starkware/starkdex-deep-dive-the-stark-core-engine-497942d0f0ab)
* [STARK Math Series](https://medium.com/starkware/tagged/stark-math)
* [Using SHARP (Shared Prover)](https://www.cairo-lang.org/docs/sharp.html)
* [Cairo for Blockchain Developers](https://www.cairo-lang.org/cairo-for-blockchain-developers/)


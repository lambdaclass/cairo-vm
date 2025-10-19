# Documentation

This folder contains extended documentation for Cairo VM. For a general overview, see the [main README](../README.md).

* [How does the Cairo VM work?](./vm/)
* [How does the original Cairo VM work?](./python_vm/)
* [Benchmarks](./benchmarks/) ([see results](./benchmarks/criterion_benchmark.pdf), [flamegraph](./benchmarks/flamegraph.svg))
* [Custom Hint Processor](./hint_processor/)
* [How to run a cairo program with custom hints](./hint_processor/builtin_hint_processor)
* [References parsing](./references_parsing/)
* [Tracer](./tracer/)
* [Debugging](./debugging.md)

## Tooling

* [cairo1-run](/cairo1-run): Execute Cairo 1 programs
* [cairo-vm-cli](/cairo-vm-cli): Execute Cairo 0 programs
* [cairo-vm-tracer](/cairo-vm-tracer)
* [fuzzer](/fuzzer)
* [hint_accountant](/hint_accountant)

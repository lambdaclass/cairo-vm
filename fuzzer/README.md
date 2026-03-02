# Fuzzers

Both fuzzers use [honggfuzz](https://github.com/google/honggfuzz) via the [honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs) crate.

## Requirements

- **Linux only** — honggfuzz does not support macOS.
- Install the honggfuzz CLI: `cargo install honggfuzz`

## fuzz_json

Generates random Cairo program JSON structures using the `arbitrary` crate, then runs them through `cairo_run`. Tests JSON deserialization and VM execution with fuzzed program data, builtins, hints, and configurations.

```
cd fuzzer
HFUZZ_RUN_ARGS="--dict=json.dict" cargo hfuzz run fuzz_json
```

## fuzz_program

Generates random `Program` structs directly (bypassing JSON) and runs them through `cairo_run_fuzzed_program` with a 1M step limit. Tests VM execution with fuzzed programs and configurations.

```
cd fuzzer
cargo hfuzz run fuzz_program
```

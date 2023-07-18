## fuzz_json
This fuzzer creates a json file directly from bytes.
`HFUZZ_RUN_ARGS="--dict=json.dict" cargo hfuzz run fuzz_json`

## cairo_compiled_programs_fuzzer
To run this fuzzer you need to be inside a py_env and be able to run cairo-compile command from the fuzzer folder beforehand.

To run the fuzzer you need to have installed Cargo-fuzz, if you don´t use the command `cargo +nightly install cargo-fuzz`

To run simply use `cargo +nightly fuzz run --fuzz-dir . cairo_compiled_programs_fuzzer`

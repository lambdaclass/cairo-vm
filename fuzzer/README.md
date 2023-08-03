## fuzz_json
This fuzzer creates a json file directly from bytes.
`HFUZZ_RUN_ARGS="--dict=json.dict" cargo hfuzz run fuzz_json`

## cairo_compiled_programs_fuzzer
To run this fuzzer you need to be able to run cairo-compile command from the fuzzer folder beforehand.

To run the fuzzer you need to have installed `cargo-fuzz`. If not, use the command `cargo +nightly install cargo-fuzz`

To run simply use `cargo +nightly fuzz run --fuzz-dir . cairo_compiled_programs_fuzzer`

We use nightly for this fuzzer because cargo fuzz runs with the -Z flag, which only works with +nightly.

## diff_fuzzer
To run de diff fuzzer on the uint256_mul_div_mod function, go to the root of the project and run
`make fuzzer-deps` if you haven't before, this should only be run once.
`make diff-fuzz`

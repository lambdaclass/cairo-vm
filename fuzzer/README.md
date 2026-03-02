## fuzz_json
This fuzzer creates a json file directly from bytes.
`HFUZZ_RUN_ARGS="--dict=json.dict" cargo hfuzz run fuzz_json`

## fuzz_program
This fuzzer generates random Cairo programs and runs them directly.
`cargo hfuzz run fuzz_program`

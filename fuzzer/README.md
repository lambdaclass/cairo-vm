## fuzz_json
This fuzzer creates a json file directly from bytes.
`HFUZZ_RUN_ARGS="--dict=json.dict" cargo hfuzz run fuzz_json`

## fuzz_cairo
Fuzzer that creates a program.cairo file, compiles it and then runs the VM
`cargo hfuzz run fuzz_cairo`

## fuzz_json
This fuzzer creates a json file directly from bytes.
`HFUZZ_RUN_ARGS="--dict=json.dict" cargo hfuzz run fuzz_json`

## fuzz_blake
Cairo VM blake2s differential fuzzer for the python and rust implementations 
make sure to activate the enviroment first
`source ../cairo-vm-env/bin/activate`
`HFUZZ_RUN_ARGS="-t 60" cargo hfuzz run fuzz_blake`

#!/usr/bin/env sh
tests_path="../cairo_programs/benchmarks"

set -e

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    export PATH="$(pyenv root)/shims:$PATH"

    hyperfine \
	    -n "Cairo VM (CPython)" "cairo-run --proof_mode --memory_file /dev/null --trace_file /dev/null --layout starknet_with_keccak --program $tests_path/$file.json" \
	    -n "cairo-vm (Rust)" "../target/release/cairo-vm-cli $tests_path/$file.json --proof_mode --memory_file /dev/null --trace_file /dev/null --layout starknet_with_keccak"
done

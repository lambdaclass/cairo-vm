#!/usr/bin/env sh
tests_path="../cairo_programs/benchmarks"

set -e

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    program="$tests_path/$file.json"
    python_command="cairo-run --proof_mode --memory_file /dev/null --trace_file /dev/null --layout starknet_with_keccak --program $program"
    rust_command="../target/release/cairo-vm-cli $program --proof_mode --memory_file /dev/null --trace_file /dev/null --layout starknet_with_keccak"

    hyperfine \
	    -n "Cairo VM (CPython)" ". ../cairo-vm-env/bin/activate && $python_command" \
	    -n "Cairo VM (PyPy)"    ". ../cairo-vm-pypy-env/bin/activate && $python_command" \
	    -n "cairo-vm (Rust)"    "$rust_command"
done

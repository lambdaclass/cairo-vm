#!/usr/bin/env sh
tests_path="cairo_programs/benchmarks"

set -e

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    export PATH="$(pyenv root)/shims:$PATH"

hyperfine -n "main" "binaries/cairo-vm-cli-main $tests_path/$file.json --layout starknet_with_keccak" -n "lambdaworks" "binaries/cairo-vm-cli-lambdaworks $tests_path/$file.json --layout starknet_with_keccak" -w 30 -r 50
done

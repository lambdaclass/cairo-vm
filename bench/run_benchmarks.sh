#!/usr/bin/env sh
tests_path="cairo_programs/benchmarks"

set -e

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    hyperfine \
        -n "cairo-rs (MAIN)" "target/release/cairo-vm-cli-main $tests_path/$file.json --layout all"\
	    -n "cairo-rs (NO_NAME)" "target/release/cairo-vm-cli $tests_path/$file.json --layout all"
done

#!/usr/bin/env sh
tests_path="cairo_programs/benchmarks"
trace_enabled=${1:-false}

set -e

source ../cairo-rs-py/scripts/cairo-rs-py/bin/activate

for input_file in "$tests_path"/*.cairo; do
    if [ -f "$input_file" ]; then
        output_file="${input_file%.cairo}.json"
        cairo-compile --cairo_path="cairo_programs" "$input_file" --output "$output_file"
        echo "Compiled $input_file to $output_file"
    fi
done

deactivate

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    export PATH="$(pyenv root)/shims:$PATH"

    if [ "$trace_enabled" = true ]; then
        hyperfine -w 0 -r 2 -i --show-output \
            -n "Cairo VM (CPython)" "source ../cairo-rs-py/scripts/cairo-lang/bin/activate && cairo-run --layout all_cairo --program $tests_path/$file.json --trace_file $tests_path/$file.trace" \
            -n "Cairo VM (PyPy)" "source ../cairo-rs-py/scripts/cairo-rs-pypy/bin/activate && cairo-run --layout all_cairo --program $tests_path/$file.json --trace_file $tests_path/$file.trace" \
            -n "cairo-rs (Rust)" "target/release/cairo-rs-run $tests_path/$file.json --layout all_cairo --trace_file $tests_path/$file.trace"
    else
        hyperfine -w 0 -r 2 -i --show-output \
            -n "Cairo VM (CPython)" "source ../cairo-rs-py/scripts/cairo-lang/bin/activate && cairo-run --layout all_cairo --program $tests_path/$file.json" \
            -n "Cairo VM (PyPy)" "source ../cairo-rs-py/scripts/cairo-rs-pypy/bin/activate && cairo-run --layout all_cairo --program $tests_path/$file.json" \
            -n "cairo-rs (Rust)" "target/release/cairo-rs-run $tests_path/$file.json --layout all_cairo"
    fi
done



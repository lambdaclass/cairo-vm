#!/usr/bin/env sh

tests_path="cairo_programs/benchmarks"
trace_enabled=${trace_enable:-false}
output_file=""
warmup=5
runs=10

while [ $# -gt 0 ]; do
  case "$1" in
    --trace_enable=*)
      trace_enabled="${1#*=}"
      ;;
    --output_file=*)
      output_file="${1#*=}"
      ;;
    --warmup=*)
      warmup="${1#*=}"
      ;;
    --runs=*)
      runs="${1#*=}"
      ;;
    *)
      echo "Invalid argument: $1"
      exit 1
      ;;
  esac
  shift
done

if [ -z "$output_file" ]; then
  echo "Error: missing --output_file parameter"
  echo "Usage: $0 --output_file=<output_file>"
  exit 1
fi

set -e

source ../cairo-rs-py/scripts/cairo-rs-py/bin/activate

for input_file in "$tests_path"/*.cairo; do
    if [ -f "$input_file" ]; then
        output_file="${input_file%.cairo}.json"
        cairo-compile --cairo_path="cairo_programs" "$input_file" --output "$output_file"
        echo "Compiled $input_file to $output_file"
    fi
done

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    export PATH="$(pyenv root)/shims:$PATH"

    if [ "$trace_enabled" = true ]; then
        hyperfine --show-output -w "$warmup" -r "$runs" \
            -n "Cairo VM (CPython)" "source ../cairo-rs-py/scripts/cairo-lang/bin/activate && cairo-run --layout all --program $tests_path/$file.json --trace_file $tests_path/$file.trace" \
            -n "Cairo VM (PyPy)" "source ../cairo-rs-py/scripts/cairo-rs-pypy/bin/activate && cairo-run --layout all --program $tests_path/$file.json --trace_file $tests_path/$file.trace" \
            -n "cairo-rs (Rust)" "target/release/cairo-rs-run $tests_path/$file.json --layout all --trace_file $tests_path/$file.trace"
    else
        hyperfine -w "$warmup" -r "$runs" \
            -n "cairo-rs (Rust)" "target/release/cairo-rs-run $tests_path/$file.json --layout all"
    fi
done

if [ -n "$output_file" ]; then
  exec > "$output_file"
fi

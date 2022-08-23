#!/usr/bin/env sh
tests_path="../cairo_programs/benchmarks"

set -e

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    export PATH="$(pyenv root)/shims:$PATH"

    hyperfine \
	    -n "Cairo VM (CPython)" "PYENV_VERSION=3.7.12 cairo-run --layout all --program $tests_path/$file.json" \
	    -n "Cairo VM (PyPy)" "PYENV_VERSION=pypy3.7-7.3.9 cairo-run --layout all --program $tests_path/$file.json" \
	    -n "Cleopatra VM (Rust)" "../target/release/cairo-rs-run $tests_path/$file.json"
done

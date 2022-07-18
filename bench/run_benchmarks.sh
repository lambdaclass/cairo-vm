#!/usr/bin/env sh
tests_path="../cairo_programs/benchmarks"

set -e
echo "Cleaning old results"
rm -f results

for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"
    echo "\n*** $file.cairo times ***" >> results

    export PATH="$(pyenv root)/shims:$PATH"

    echo "\nOriginal Cairo VM:"
    pyenv local 3.7.12
    hyperfine "cairo-run --layout all --program $tests_path/$file.json"

    echo "\nPyPy Cairo VM:"
    pyenv local pypy3.7-7.3.9
    hyperfine "cairo-run --layout all --program $tests_path/$file.json"

    echo "\nRust Cleopatra VM:"
    hyperfine "../target/release/cleopatra-run $tests_path/$file.json"
done

cat results

echo "Cleaning results"
rm -f results

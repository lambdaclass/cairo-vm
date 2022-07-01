#!/usr/bin/env sh

tests_path="../cairo_programs"

rm -f $tests_path/*.json
rm -f $tests_path/*.trace
rm -f $tests_path/*.memory

test_files=($(ls -p $tests_path | grep -v / | sed -E 's/\.cairo//'))

for file in ${test_files[@]}; do
    cairo-compile "$tests_path/$file.cairo" --output "$tests_path/$file.json"
done

cairo-run --program $tests_path/struct.json --trace_file $tests_path/struct.trace --memory_file $tests_path/struct.memory

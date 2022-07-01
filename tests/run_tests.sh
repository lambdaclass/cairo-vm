#!/bin/bash

rm -f ../cairo_programs/*.json
rm -f ../cairo_programs/*.trace
rm -f ../cairo_programs/*.memory

test_files=($(ls -p ../cairo_programs | grep -v / | sed -E 's/\.cairo//'))

for file in ${test_files[@]}; do
    cairo-compile "../cairo_programs/$file.cairo" --output "../cairo_programs/$file.json"
done

cairo-run --program ../cairo_programs/struct.json --trace_file ../cairo_programs/struct.trace --memory_file ../cairo_programs/struct.memory

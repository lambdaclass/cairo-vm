#!/bin/bash

rm -f *.json

test_files=($(ls -p ../cairo_programs | grep -v / | sed -E 's/\.cairo//'))

for file in ${test_files[@]}; do
    cairo-compile "../cairo_programs/$file.cairo" --output "$file.json"
done

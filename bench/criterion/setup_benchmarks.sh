#!/bin/bash

rm *.json

test_files=("integration" "fibonacci_1000" "linear-search")

for file in ${test_files[@]}; do
    cairo-compile "../../cairo_programs/$file.cairo" --output "$file.json"
done

rm *.json

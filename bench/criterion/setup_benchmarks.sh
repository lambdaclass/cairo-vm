#!/bin/bash

rm ../../cairo_programs/*.json

test_files=("bin-search")

for file in ${test_files[@]}; do
    cairo-compile "../../cairo_programs/$file.cairo" --output "../../cairo_programs/$file.json"
done

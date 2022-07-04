#!/usr/bin/env sh

tests_path="../cairo_programs"

for file in $(ls $tests_path | grep .trace | sed -E 's/(\.cleopatra)?\.trace//'); do
    if ! diff -q $tests_path/$file{,.cleopatra}.trace; then
        echo "Traces for $file differ"
        exit 1
    else
        echo "Traces for $file match"
    fi
done

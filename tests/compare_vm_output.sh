#!/usr/bin/env sh

tests_path="../cairo_programs"
exit_code=0

for file in $(ls $tests_path | grep .cleopatra.trace | sed -E 's/\.cleopatra\.trace//'); do
    if ! diff -q $tests_path/$file{,.cleopatra}.trace; then
        echo "Traces for $file differ"
        exit_code=1
    else
        echo "Traces for $file match"
    fi
done

for file in $(ls $tests_path | grep .cleopatra.memory | sed -E 's/\.cleopatra\.memory//'); do
    if ! diff -q $tests_path/$file{,.cleopatra}.memory; then
        echo "Memory differs for $file"
        exit_code=1
    else
        echo "Memory mateches for $file"
    fi
done

exit "${exit_code}"

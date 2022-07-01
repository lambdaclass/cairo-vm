#!/usr/bin/env bash

tests_path="../cairo_programs"

rm -f $tests_path/*.trace
rm -f $tests_path/*.json

test_files=($(ls -p $tests_path | grep -v / | grep -v .json | sed -E 's/\.cairo//'))

cargo build --release

for file in ${test_files[@]}; do
    cairo-compile "$tests_path/$file.cairo" --output "$tests_path/$file.json"

    cairo_output=$( (cairo-run --layout all --print_output --program "$tests_path/$file.json" --trace_file "$tests_path/$file.trace") | tr -dc 0-9 ) 
    cleopatra_output=$( (../target/release/cleopatra-run --print_output "$tests_path/$file.json" --trace_file "$tests_path/$file.cleopatra.trace") | tr -dc 0-9 )

    if [[ $cairo_output != $cleopatra_output ]]; then
        echo "Warning: Cairo output ($cairo_output) and Cleopatra output ($cleopatra_output) differ"
    fi

    if ! diff -q $tests_path/$file{,.cleopatra}.trace; then
        echo "Traces for $file differ"
        exit 1
    else
        echo "Traces for $file match"
    fi
done

rm $tests_path/*.trace
rm $tests_path/*.json
